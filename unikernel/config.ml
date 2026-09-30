open Mirage

(* Mirage initializes and feeds Fortuna from target entropy before Main.start. *)
let main = main "Unikernel.Main" ~packages:[ package "bitcoin" ] (job @-> job)
let () = register ~random:default_random "bitcoin-smoke" [ main $ noop ]
