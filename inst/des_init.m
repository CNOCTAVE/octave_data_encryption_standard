## Copyright (C) 2026 Yu Hongbo <yuhongbo@member.fsf.org>, CNOCTAVE
## SPDX-License-Identifier: GPL-3.0-or-later
##
## -*- texinfo -*-
## @deftypefn {} {} des_init ()
## Register the four dynamically loaded functions contained in des_core.oct.
## Safe to call repeatedly.  Every public wrapper in this package calls it.
## @end deftypefn
function core = des_init ()
  persistent initialized
  persistent core_path
  if (isempty (initialized))
    initialized = false;
  endif
  if (isempty (core_path))
    core_path = '';
  endif

  if (initialized)
    core = core_path;
    return;
  endif

  here = fileparts (which ('des_init'));
  core = fullfile (here, 'des_core.oct');
  if (isempty (dir (core)))
    parent = fileparts (here);
    core = fullfile (parent, 'src', 'des_core.oct');
  endif
  if (isempty (dir (core)))
    error ('des_init: des_core.oct not found; add the package directory to the path');
  endif

  autoload ('des_blockcrypt_core', core);
  autoload ('des3_ecb_crypt', core);
  autoload ('qrc_xor_pre', core);
  autoload ('qrc_raw_decrypt', core);

  initialized = true;
  core_path = core;
endfunction
