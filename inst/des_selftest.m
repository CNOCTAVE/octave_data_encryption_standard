## Copyright (C) 2026 Yu Hongbo <yuhongbo@member.fsf.org>, CNOCTAVE
## SPDX-License-Identifier: GPL-3.0-or-later
##
## -*- texinfo -*-
## @deftypefn {} {} des_selftest ()
## Run two independent checks and print their outcome:
## @enumerate
## @item FIPS 46-3 known-answer test (key 133457799BBCDFF1,
## plaintext 0123456789ABCDEF -> ciphertext 85E813540F0AB405).
## @item QRC round trip: 3DES-ECB encrypt/decrypt of an 8-byte block in the
## qqmusic bit order.
## @end enumerate
## @end deftypefn
function des_selftest ()
  des_init ();
  h = @(s) reshape (uint8 (hex2dec (reshape (s, 2, [])')), 1, []);

  pt = h ('0123456789ABCDEF');
  key = h ('133457799BBCDFF1');
  ct = des_blockcrypt (pt, key, 1, 'standard');
  expected = h ('85E813540F0AB405');
  fips_ok = isequal (ct, expected) && ...
            isequal (des_blockcrypt (ct, key, 0, 'standard'), pt);
  printf ('FIPS 46-3 known-answer test: %s\n', ternary (fips_ok, 'PASS', 'FAIL'));

  qq_ct = des_blockcrypt (pt, key, 1, 'qqmusic');
  qq_ok = isequal (des_blockcrypt (qq_ct, key, 0, 'qqmusic'), pt);
  printf ('qqmusic bit-order round trip: %s\n', ternary (qq_ok, 'PASS', 'FAIL'));

  if (! (fips_ok && qq_ok))
    error ('des_selftest: failed');
  endif
endfunction

function s = ternary (cond, a, b)
  if (cond)
    s = a;
  else
    s = b;
  endif
endfunction
