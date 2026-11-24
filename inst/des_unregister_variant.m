## Copyright (C) 2026 Yu Hongbo <yuhongbo@member.fsf.org>, CNOCTAVE
## SPDX-License-Identifier: GPL-3.0-or-later
## Remove a named custom variant registered with des_register_variant.
function des_unregister_variant (name)
  if (nargin < 1)
    print_usage ();
  endif
  des_variant_registry ('unregister', char (name));
endfunction
