(* Emits lib/bip39_wordlist.ml from the BIP39 English wordlist. *)

let () =
  let path = Sys.argv.(1) in
  let ic = open_in path in
  let words = ref [] in
  (try
     while true do
       let w = String.trim (input_line ic) in
       if w <> "" then words := w :: !words
     done
   with End_of_file -> ());
  close_in ic;
  let words = Array.of_list (List.rev !words) in
  if Array.length words <> 2048 then (
    Printf.eprintf "gen_wordlist: expected 2048 words, got %d\n" (Array.length words);
    exit 1);
  print_string
    "(* Generated from bip39/english.txt by bip39/gen/gen_wordlist.ml.\n\
    \   Do not edit. *)\n\n\
     let words =\n\
    \  [|\n";
  Array.iter (fun w -> Printf.printf "    %S;\n" w) words;
  print_string "  |]\n"
