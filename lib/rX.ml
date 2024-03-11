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
open Sexplib.Std

module Request = struct
  type t = {
    id: int;
    gref: int32;
  } [@@deriving sexp]

  let get_req_id b = Cstruct.LE.get_uint16 b 0
  let get_req_gref b = Cstruct.LE.get_uint32 b 4
  let set_req_id b = Cstruct.LE.set_uint16 b 0
  let set_req_gref b = Cstruct.LE.set_uint32 b 4

  let write t slot =
    set_req_id slot t.id;
    set_req_gref slot t.gref

  let read slot =
    let id = get_req_id slot in
    let gref = get_req_gref slot in
    { id; gref }
end

module Response = struct
  type error = int

  type t = {
    id: int;
    offset: int;
    flags: Flags.t;
    size: (int, error) result;
  }

  let get_resp_id b = Cstruct.LE.get_uint16 b 0
  let get_resp_offset b = Cstruct.LE.get_uint16 b 2
  let get_resp_flags b = Cstruct.LE.get_uint16 b 4
  let get_resp_status b = Cstruct.LE.get_uint16 b 6
  let set_resp_id b = Cstruct.LE.set_uint16 b 0
  let set_resp_offset b = Cstruct.LE.set_uint16 b 2
  let set_resp_flags b = Cstruct.LE.set_uint16 b 4
  let set_resp_status b = Cstruct.LE.set_uint16 b 6

  let within_page name x =
    if x < 0 || x > 4096
    then Error (Printf.sprintf "%s is corrupt: expected 0 <= %s <= 4096 but got %d" name name x)
    else Ok x

  let read slot =
    let ( let* ) = Result.bind in
    let id = get_resp_id slot in
    let offset = get_resp_offset slot in
    let* offset = within_page "RX.Response.offset" offset in
    let flags = Flags.of_int (get_resp_flags slot) in
    let size =
      match get_resp_status slot with
      | status when status > 0 -> Ok status
      | status -> Error status in
    Ok { id; offset; flags; size }

  let write t slot =
    set_resp_id slot t.id;
    set_resp_offset slot t.offset;
    set_resp_flags slot (Flags.to_int t.flags);
    match t.size with
    | Ok size ->
        assert (size > 0);
        set_resp_status slot size
    | Error st ->
        assert (st < 0);
        set_resp_status slot st

  let flags t = t.flags
  let size t = t.size
end

let total_size = 8
