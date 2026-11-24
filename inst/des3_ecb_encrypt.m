## Copyright (C) 2026 Yu Hongbo <yuhongbo@member.fsf.org>, CNOCTAVE
## SPDX-License-Identifier: GPL-3.0-or-later
##
## -*- texinfo -*-
## @deftypefn {} {} des3_ecb_encrypt (@var{data}, @var{key24}, @var{variant})
## Encrypt @var{data} (uint8 vector, length a multiple of 8) with 3DES-ECB.
## @var{variant} is "qqmusic" (default) or "standard".
## @end deftypefn
function out = des3_ecb_encrypt (data, key24, variant = 'qqmusic')
  des_init ();
  out = des3_ecb_crypt (data, key24, 1, variant);
endfunction
