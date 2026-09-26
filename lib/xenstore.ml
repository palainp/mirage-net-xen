(*
 * Copyright (c) 2013,2014 Citrix Systems Inc
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)
open Lwt

let src = Logs.Src.create "net-xen xenstore" ~doc:"mirage-net-xen's XenStore client"
module Log = (val Logs.src_log src : Logs.LOG)

let (/) a b =
  if a = "" then b
  else if b = "" then a
  else (
    let b =
      if b.[0] = '/' then String.sub b 1 (String.length b - 1)
      else b in
    if a = "/" then a ^ b
    else if a.[String.length a - 1] = '/' then a ^ b
    else a ^ "/" ^ b
  )

module Make(Xs: Xs_client_lwt.S) = struct
  open S

  let read_int x =
    try
      return (int_of_string x)
    with _ ->
      fail (Failure (Printf.sprintf "Expected an integer: %s" x))

  let read_int32 x =
    try
      return (Int32.of_string x)
    with _ ->
      fail (Failure (Printf.sprintf "Expected a 32-bit integer: %s" x))

  (* To my understanding from the linux netback code, the state machine is:
     [Unknown] -(a)-> [InitWait] --(b)--> [Connected]
                         ^    |                  |
                    (f)  |    \ (d)              | (c)
                         |     \                 |
                      [Closed]  \--> [Closing] <-/
                         ^                 |
                         \-------(e)-------/

    with a) publish backend features
         b) read frontend features, map rings, bind the channel, etc.
         c) free mappings, unbind channel
         d) do nothing apart publishing the state: this is special for windows PV,
            it uses two netif (one for the guest and the other for the -dm and give
            up for the -dm's one)
         e) guest is leaving, do nothing apart publishing the state
         f) features are already published, do nothing apart publishing the state *)

  exception Client_gone

  (* What is the target state when we see the frontend's one *)
  let target =
    function
    | Xen_os.Device_state.Initialising -> Some Xen_os.Device_state.InitWait
    | Xen_os.Device_state.Connected -> Some Xen_os.Device_state.Connected
    | Xen_os.Device_state.Closing -> Some Xen_os.Device_state.Closing
    | Xen_os.Device_state.Closed
    | Xen_os.Device_state.Unknown -> Some Xen_os.Device_state.Closed
    | Xen_os.Device_state.InitWait
    | Xen_os.Device_state.Initialised
    | Xen_os.Device_state.Reconfiguring
    | Xen_os.Device_state.Reconfigured -> None (* All these does not appear to be written by frontend... *)

  (* What state we should write when we are in [current], and we want to move to [target] (multiple
     iterations and state transition might be required) *)
  let next_state current target =
    match current, target with
    | Xen_os.Device_state.InitWait, Xen_os.Device_state.Connected -> Xen_os.Device_state.Connected
    | Xen_os.Device_state.InitWait, Xen_os.Device_state.Closing
    | Xen_os.Device_state.InitWait, Xen_os.Device_state.Closed -> Xen_os.Device_state.Closing

    | Xen_os.Device_state.Connected, Xen_os.Device_state.InitWait
    | Xen_os.Device_state.Connected, Xen_os.Device_state.Closing
    | Xen_os.Device_state.Connected, Xen_os.Device_state.Closed -> Xen_os.Device_state.Closing

    | Xen_os.Device_state.Closing, Xen_os.Device_state.InitWait
    | Xen_os.Device_state.Closing, Xen_os.Device_state.Connected
    | Xen_os.Device_state.Closing, Xen_os.Device_state.Closed -> Xen_os.Device_state.Closed

    | Xen_os.Device_state.Closed, Xen_os.Device_state.InitWait
    | Xen_os.Device_state.Closed, Xen_os.Device_state.Connected -> Xen_os.Device_state.InitWait

    | Xen_os.Device_state.Closed, Xen_os.Device_state.Closing -> Xen_os.Device_state.Closing
    | _, _ -> invalid_arg "next_state"

  (* State at [path]; a missing node reads as Unknown *)
  let read_state h path =
    Lwt.catch
      (fun () -> Xs.read h (path / "state") >|= Xen_os.Device_state.of_string)
      (function
        | Xs_protocol.Enoent _ -> return Xen_os.Device_state.Unknown
        | ex -> fail ex)

  (* A watcher that scan the frontend state change *)
  let frontend_change xsc path seen =
    Xs.wait xsc (fun h ->
      read_state h path >>= fun s ->
      if Some s = seen then fail Xs_protocol.Eagain else return s)

  (* Tell if the frontend is gone from the backend POV *)
  let removed xsc backend state =
    match state with
    | Xen_os.Device_state.Unknown -> return true
    | Xen_os.Device_state.Closed ->
      Lwt.catch
        (fun () -> Xs.(immediate xsc (fun h -> read h (backend / "online"))) >|= (<>) "1")
        (fun _ -> return true)
    | _ -> return false

  (* Track the frontend state and move accordingly following the state machine. The function walks
     through the state transitions until something needs to be done (at b during connexion and e when we call
     disconnect_backend) where it returns (). So we only need to call follow and when it returns we need to do something *)
  let follow xsc ~frontend ~backend ~until current =
    let write state =
      Xs.(immediate xsc (fun h -> write h (backend / "state") (Xen_os.Device_state.to_string state))) in
    let rec walk current t =
      if (until = `Closed && current = Xen_os.Device_state.Closed) || current = t then Lwt.return (Some current)
      else
        let next = next_state current t in
        if until = `Connect && next = Xen_os.Device_state.Connected then Lwt.return None
        else write next >>= fun () -> walk next t
    in
    let rec loop current seen =
      if (until = `Closed && current = Xen_os.Device_state.Closed) then Lwt.return_unit
      else
        frontend_change xsc frontend seen >>= fun frontend_state ->
        (match target frontend_state with
          | Some t -> walk current t
          | None -> Lwt.return (Some current))
        >>= function
        | None -> Lwt.return_unit
        | Some current ->
          removed xsc backend frontend_state >>= function
          | true -> fail Client_gone
          | false -> loop current (Some frontend_state)
    in
    loop current None

  (* Return the path of the frontend *)
  let frontend = function
  | `Client devid ->
    return (Printf.sprintf "device/vif/%d/" devid)
  | `Server (domid, devid) ->
    Xs.make ()
    >>= fun xsc ->
    Xs.(immediate xsc (fun h -> read h (Printf.sprintf "backend/vif/%d/%d/frontend" domid devid)))

  let backend = function
  | `Client devid ->
    Xs.make ()
    >>= fun xsc ->
    Xs.(immediate xsc (fun h -> read h (Printf.sprintf "device/vif/%d/backend" devid)))
  | `Server (domid, devid) ->
    return (Printf.sprintf "backend/vif/%d/%d" domid devid)

  let read_frontend_mac id =
    frontend id
    >>= fun frontend ->
    Xs.make ()
    >>= fun xsc ->
    Xs.(immediate xsc (fun h -> read h (frontend / "mac")))
    >|= Macaddr.of_string
    >>= function
    | Ok x -> return x
    | Error (`Msg msg) ->
      let m = Macaddr.make_local (fun _ -> Random.int 255) in
      Log.info (fun f -> f "%s: no configured MAC (error: %s), using %a"
        (id_to_string id) msg Macaddr.pp m);
      return m

  (* Curiously, libxl writes the frontend MAC to both the frontend and
     backend directories. The convention seems to be to use this as the
     backend MAC. See: https://github.com/QubesXen_os/qubes-issues/issues/5013 *)
  let backend_mac = Macaddr.of_string_exn "fe:ff:ff:ff:ff:ff"
  let read_backend_mac _ = return backend_mac

  let read_mtu id =
    frontend id
    >>= fun frontend ->
    Xs.make ()
    >>= fun xsc ->
    Lwt.catch
      (fun () ->
         Xs.(immediate xsc (fun h -> read h (frontend / "mtu")))
         >|= int_of_string)
      (fun _ -> return 1500)

  let read_features side path =
    Xs.make ()
    >>= fun xsc ->
    Xs.(immediate xsc
      (fun h ->
        let read_feature key =
          Lwt.catch
            (fun () ->
              read h (path / key)
              >>= fun v ->
              return (v = "1"))
            (fun _ -> return false) in
        read_feature "feature-sg"
        >>= fun sg ->
        read_feature "feature-gso-tcpv4"
        >>= fun gso_tcpv4 ->
        begin match side with
        | `Client -> read_feature "request-rx-copy"
        | `Server -> read_feature "feature-rx-copy"
        end
        >>= fun rx_copy ->
        read_feature "feature-rx-flip"
        >>= fun rx_flip ->
        read_feature "feature-rx-notify"
        >>= fun rx_notify ->
        read_feature "feature-smart-poll"
        >>= fun smart_poll ->
        return { Features.sg; gso_tcpv4; rx_copy; rx_flip; rx_notify; smart_poll }
    )
  )

  let write_features h path side features =
    let open Features in
    let write_feature k v =
      Xs.write h (path / k) (if v then "1" else "0") in
    write_feature "feature-sg" features.sg
    >>= fun () ->
    write_feature "feature-gso-tcpv4" features.gso_tcpv4
    >>= fun () ->
    begin match side with
    | `Client -> write_feature "request-rx-copy" features.rx_copy
    | `Server -> write_feature "feature-rx-copy" features.rx_copy
    end
    >>= fun () ->
    write_feature "feature-rx-flip" features.rx_flip
    >>= fun () ->
    write_feature "feature-rx-notify" features.rx_notify
    >>= fun () ->
    write_feature "feature-smart-poll" features.smart_poll

  let write_frontend_configuration id (f: frontend_configuration) =
    frontend id
    >>= fun frontend ->
    Xs.make ()
    >>= fun xsc ->
    Xs.(transaction xsc (fun h ->
      let wrfn k v = write h (frontend / k) v in
      wrfn "tx-ring-ref" (Int32.to_string f.tx_ring_ref) >>= fun () ->
      wrfn "rx-ring-ref" (Int32.to_string f.rx_ring_ref) >>= fun () ->
      wrfn "event-channel" f.event_channel >>= fun () ->
      write_features h frontend `Client f.feature_requests
    ))

  let read_frontend_configuration id =
    frontend id
    >>= fun frontend ->
    backend id
    >>= fun backend ->
    Xs.make ()
    >>= fun xsc ->
    Xs.(immediate xsc (fun h -> read_state h backend)) >>= fun current ->
    follow xsc ~frontend ~backend ~until:`Connect current >>= fun () ->
    Xs.(immediate xsc
      (fun h ->
        read h (frontend / "tx-ring-ref")
        >>= fun tx_ring_ref ->
        read_int32 tx_ring_ref
        >>= fun tx_ring_ref ->
        read h (frontend / "rx-ring-ref")
        >>= fun rx_ring_ref ->
        read_int32 rx_ring_ref
        >>= fun rx_ring_ref ->
        read h (frontend / "event-channel")
        >>= fun event_channel ->
        read_features `Client frontend
        >>= fun feature_requests ->
        return { tx_ring_ref; rx_ring_ref; event_channel; feature_requests }
      )
    )

  let wait_until_backend_connected conf =
    Xs.make () >>= fun xsc ->
    Xs.wait xsc (fun h ->
      Lwt.catch
        (fun () ->
          Xs.read h (conf.backend / "state") >>= fun state ->
          let open Xen_os.Device_state in
          match of_string state with
          | Connected -> return ()
          | Initialised
          | Unknown
          | Initialising
          | InitWait
          | Closing
          | Closed        (* XXX: stop waiting? *)
          | Reconfigured  (* XXX: stop waiting? *)
          | Reconfiguring -> fail Xs_protocol.Eagain
        )
        (function
          | Xs_protocol.Enoent _ -> fail Xs_protocol.Eagain
          | ex -> fail ex
        )
    )

  let connect id =
    Xs.make ()
    >>= fun xsc ->
    Xs.(immediate xsc (fun h ->
      ( match id with
        | `Client _ -> frontend id
        | `Server (_, _) -> backend id )
      >>= fun path ->
      write h (path / "state") Xen_os.Device_state.(to_string Connected)
    ))

  let init_backend id features =
    backend id
    >>= fun backend ->
    Xs.make ()
    >>= fun xsc ->
    Xs.(transaction xsc (fun h ->
      write_features h backend `Server features
      >>= fun () ->
      write h (backend / "state") Xen_os.Device_state.(to_string InitWait)
    ))
    >>= fun () ->
    Xs.(immediate xsc (fun h ->
      read h (backend / "frontend-id")
      >>= read_int
      >>= fun frontend_id ->
      frontend id
      >>= fun frontend ->
      read h (frontend / "backend-id")
      >>= fun backend_id ->
      read_int backend_id
      >>= fun backend_id ->
      read h (frontend / "backend")
      >>= fun backend ->
      return { frontend_id; backend; backend_id; features_available = features }
    ))


  let read_backend id =
    frontend id
    >>= fun frontend ->
    Xs.make ()
    >>= fun xsc ->
    Xs.(immediate xsc (fun h ->
      (* [safe_read] waits for the path to exists before reading it *)
      let safe_read path =
         Xs.wait xsc (fun h ->
           Lwt.catch
             (fun () ->
               Xs.read h path
             )
             (function
               | Xs_protocol.Enoent _
               | Xs_protocol.Invalid
               | Xs_protocol.Eagain -> fail Xs_protocol.Eagain
               | Xs_protocol.Eexist -> fail Xs_protocol.Eexist
               | ex -> fail ex
             )
         )
      in
      begin match id with
      | `Client _ -> read h "domid" >>= read_int
      | `Server (frontend_id, _) -> return frontend_id
      end
      >>= fun frontend_id ->
      safe_read (frontend / "backend-id")
      >>= fun backend_id ->
      read_int backend_id
      >>= fun backend_id ->
      safe_read (frontend / "backend")
      >>= fun backend ->
      read_features `Server backend
      >>= fun features_available ->
      return { frontend_id; backend; backend_id; features_available }
   ))

  let enumerate () =
    Xs.make ()
    >>= fun xsc ->
    Lwt.catch
      (fun () -> Xs.(immediate xsc (fun h -> directory h "device/vif")))
      (function
        | Xs_protocol.Enoent _ -> return []
        | e ->
          Log.warn (fun f -> f "enumerate caught exception: %s" (Printexc.to_string e));
          return []
      )

  let description = "Configuration information will be shared via Xenstore keys"

  let closing path =
    Xs.make ()
    >>= fun xsc ->
    Xs.wait xsc (fun h ->
        Lwt.try_bind
          (fun () ->
             Xs.read h (path / "state")
          )
          (fun state ->
             match Xen_os.Device_state.of_string state with
             | Xen_os.Device_state.Closing | Closed -> return ()
             | _ -> Lwt.fail Xs_protocol.Eagain
          )
          (fun ex ->
             Log.warn (fun f -> f "Error reading device state at %S: %a" path Fmt.exn ex);
             Lwt.return ()
          )
    )

  let wait_for_frontend_closing id = frontend id >>= closing
  let wait_for_backend_closing id = backend id >>= closing

  let disconnect_frontend id =
    Xs.make ()
    >>= fun xsc ->
    frontend id
    >>= fun path ->
    Xs.(immediate xsc (fun h ->
      write h (path / "state") Xen_os.Device_state.(to_string Closed)
    ))

  (* See: https://github.com/mirage/xen/commit/546678c6a60f64fb186640460dfa69a837c8fba5 *)
  let disconnect_backend id =
    Xs.make ()
    >>= fun xsc ->
    frontend id
    >>= fun frontend ->
    backend id
    >>= fun backend ->
    Lwt.catch (fun () ->
        Xs.(immediate xsc (fun h -> read_state h backend)) >>= fun current ->
        (match current with
         (* Connected: the frontend went to Closing, and we're called by cleanup for disconnection -> move to Closing
            InitWait: the frontend give up early -> move to Closing
            Other states: we want to disconnect, follow the state machine from the current state *)
         | InitWait | Connected ->
           Xs.(immediate xsc (fun h -> write h (backend / "state") (Xen_os.Device_state.to_string Closing)))
           >|= fun () -> Xen_os.Device_state.Closing
         | s -> return s)
        >>= fun current ->
        follow xsc ~frontend ~backend ~until:`Closed current
      )
      (function
        | Client_gone
        | Xs_protocol.Enoent _ -> return ()
        | ex ->
         Log.warn (fun f -> f "XenStore error removing %S: %a" frontend Fmt.exn ex);
         Lwt.return_unit
      )
end
