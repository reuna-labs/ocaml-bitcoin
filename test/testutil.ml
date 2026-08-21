(* Shared helpers. The test binary is an ordinary Unix executable -- only
   [lib/] carries the no-Unix constraint -- so reading fixtures from disk is
   fine here. *)

let hex = Ohex.decode
let unhex = Ohex.encode
let vector name = Filename.concat "vectors" name
let json name = Yojson.Safe.from_file (vector name)

let ok = function
  | Ok x -> x
  | Error e ->
      Alcotest.failf "unexpected error: %s" (Bitcoin.Error.to_string (e :> Bitcoin.Error.t))

let is_error what = function
  | Error _ -> ()
  | Ok _ -> Alcotest.failf "%s: expected an error, got Ok" what

let check_hex name expected got = Alcotest.(check string) name expected (unhex got)
let check_str = Alcotest.(check string)
let check_bool = Alcotest.(check bool)
let check_int = Alcotest.(check int)
