(*
 * Copyright (c) 2010-2013 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2014-2015 Citrix Inc
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

module Extra = struct
  type t = {
    typ : int;       (* uint8 *)
    flags : int;     (* uint8 *)
    gso_size : int;  (* uint16 *)
    gso_type : int;  (* uint8 *)
    gso_pad : int;   (* uint8 *)
  }

  let get_extra_type c = Cstruct.get_uint8 c 0
  let get_extra_flags c = Cstruct.get_uint8 c 1
  let get_extra_gso_size c = Cstruct.LE.get_uint16 c 2
  let get_extra_gso_type c = Cstruct.get_uint8 c 4
  let get_extra_gso_pad c = Cstruct.get_uint8 c 5

  let set_extra_type c typ = Cstruct.set_uint8 c 0 typ
  let set_extra_flags c flags = Cstruct.set_uint8 c 1 flags
  let set_extra_gso_size c size = Cstruct.LE.set_uint16 c 2 size
  let set_extra_gso_type c typ = Cstruct.set_uint8 c 4 typ
  let set_extra_gso_pad c pad = Cstruct.set_uint8 c 5 pad

  let sizeof_extra = 8

  let read slot =
    let typ = get_extra_type slot in
    let flags = get_extra_flags slot in
    (* Type values:
       0 -> None
       1 -> NETIF_EXTRA_TYPE_CSUM
       2 -> NETIF_EXTRA_TYPE_GSO
       3 -> NETIF_EXTRA_TYPE_TSO *)
    if typ = 2 then ( (* NETIF_EXTRA_TYPE_GSO *)
      let gso_size = get_extra_gso_size slot in
      let gso_type = get_extra_gso_type slot in (* GSO type = 1 for TCPv4 *)
      let gso_pad = get_extra_gso_pad slot in
      Ok { typ; flags; gso_size; gso_type; gso_pad }
    ) else (
      Ok { typ; flags; gso_size=0; gso_type=0; gso_pad=0 }
    )

  let write t slot =
    set_extra_type slot t.typ;
    set_extra_flags slot t.flags;
    if t.typ = 2 then ( (* NETIF_EXTRA_TYPE_GSO *)
      set_extra_gso_size slot t.gso_size;
      set_extra_gso_type slot t.gso_type;
      set_extra_gso_pad slot t.gso_pad
    )
end

module Request = struct
  type error = { impossible : 'a. 'a }

  type t = {
    gref: int32;
    offset: int;
    flags: Flags.t;
    id: int;

    (* For frames split over multiple requests, first.size is the total
       size of the frame. Each of the following requests gives the size
       of that fragment. The receiver recovers the actual size of the
       first fragment by subtracting all of the other sizes. *)
    size: int;
    extras: Extra.t list;
  }

  let get_req_gref c = Cstruct.LE.get_uint32 c 0
  let set_req_gref c gref = Cstruct.LE.set_uint32 c 0 gref
  let get_req_offset c = Cstruct.LE.get_uint16 c 4
  let set_req_offset c off = Cstruct.LE.set_uint16 c 4 off
  let get_req_flags c = Cstruct.LE.get_uint16 c 6
  let set_req_flags c flags = Cstruct.LE.set_uint16 c 6 flags
  let get_req_id c = Cstruct.LE.get_uint16 c 8
  let set_req_id c id = Cstruct.LE.set_uint16 c 8 id
  let get_req_size c = Cstruct.LE.get_uint16 c 10
  let set_req_size c size = Cstruct.LE.set_uint16 c 10 size
  let sizeof_req = 12

  let write t slot =
    let flags = Flags.to_int t.flags in
    set_req_gref slot t.gref;
    set_req_offset slot t.offset;
    set_req_flags slot flags;
    set_req_id slot t.id;
    set_req_size slot t.size

  let within_page name x =
    if x < 0 || x > 4096
    then Error (Printf.sprintf "%s is corrupt: expected 0 <= %s <= 4096 but got %d" name name x)
    else Ok x

  let read slot =
    let ( let* ) = Result.bind in
    let gref = get_req_gref slot in
    let offset = get_req_offset slot in
    let* offset = within_page "TX.Request.offset" offset in
    let flags = Flags.of_int (get_req_flags slot) in
    let id = get_req_id slot in
    let size = get_req_size slot in
    Ok { gref; offset; flags; id; size; extras=[]; }

  let flags t = t.flags

  let size t =
    let req_size = t.size in
    let extra_size = List.fold_left (fun acc extra ->
      acc + extra.Extra.gso_size
    ) 0 t.extras in
    Ok (req_size + extra_size)
end

module Response = struct
  type status =
    | DROPPED
    | ERROR
    | OKAY
    | NULL

  let status_to_int = function
    | DROPPED -> 0xfffe
    | ERROR -> 0xffff
    | OKAY -> 0
    | NULL -> 1

  let int_to_status = function
    | 0xfffe -> Some DROPPED
    | 0xffff -> Some ERROR
    | 0 -> Some OKAY
    | 1 -> Some NULL
    | _ -> None

  type t = {
    id: int;
    status: status;
  }

  let get_resp_id c = Cstruct.LE.get_uint16 c 0
  let set_resp_id c id = Cstruct.LE.set_uint16 c 0 id
  let get_resp_status c = Cstruct.LE.get_uint16 c 2
  let set_resp_status c status = Cstruct.LE.set_uint16 c 2 status
  let sizeof_resp = 4

  let write t slot =
    set_resp_id slot t.id;
    set_resp_status slot (status_to_int t.status)

  let read slot =
    let id = get_resp_id slot in
    let st = get_resp_status slot in
    match int_to_status st with
    | None -> failwith (Printf.sprintf "Invalid TX.Response.status %d" st)
    | Some status -> { id; status }
end

let total_size = max Request.sizeof_req (max Response.sizeof_resp Extra.sizeof_extra)
let () = assert(total_size = 12)
