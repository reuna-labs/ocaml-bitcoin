open Mirage

let main = main "Unikernel.Main" ~packages:[ package "bitcoin" ] job
let () = register "bitcoin-smoke" [ main ]
