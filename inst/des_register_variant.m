## Copyright (C) 2026 Yu Hongbo <yuhongbo@member.fsf.org>, CNOCTAVE
## SPDX-License-Identifier: GPL-3.0-or-later
##
## -*- texinfo -*-
## @deftypefn {} {} des_register_variant (@var{name}, @var{encrypt_fn}, @var{decrypt_fn})
## Register a named custom block cipher for @code{des_blockcrypt}.
## Both handlers are function handles with signature
## @code{out = fn (block, key, direction)} returning 8 bytes.
## @end deftypefn
function des_register_variant (name, encrypt_fn, decrypt_fn)
  if (nargin < 3)
    print_usage ();
  endif
  if (! (isa (encrypt_fn, 'function_handle') && isa (decrypt_fn, 'function_handle')))
    error ('des_register_variant: encrypt_fn and decrypt_fn must be function handles');
  endif
  des_variant_registry ('register', char (name), encrypt_fn, decrypt_fn);
endfunction
