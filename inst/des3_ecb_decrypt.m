## Copyright (C) 2026 Yu Hongbo <yuhongbo@member.fsf.org>, CNOCTAVE
## SPDX-License-Identifier: GPL-3.0-or-later
##
## -*- texinfo -*-
## @deftypefn {} {} des3_ecb_decrypt (@var{data}, @var{key24}, @var{variant})
## Decrypt @var{data} (uint8 vector, length a multiple of 8) with 3DES-ECB.
## @var{variant} is "qqmusic" (default, the private bit order used by
## LyricTools.exe) or "standard" (FIPS 46-3).
## @end deftypefn
function out = des3_ecb_decrypt (data, key24, variant = 'qqmusic')
  des_init ();
  out = des3_ecb_crypt (data, key24, 0, variant);
endfunction
