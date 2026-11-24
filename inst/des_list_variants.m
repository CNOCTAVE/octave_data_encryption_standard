## Copyright (C) 2026 Yu Hongbo <yuhongbo@member.fsf.org>, CNOCTAVE
## SPDX-License-Identifier: GPL-3.0-or-later
## Return a cell array with the names of all registered custom variants.
function names = des_list_variants ()
  names = des_variant_registry ('list');
endfunction
