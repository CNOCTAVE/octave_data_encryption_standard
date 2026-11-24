## Copyright (C) 2026 Yu Hongbo <yuhongbo@member.fsf.org>, CNOCTAVE
## SPDX-License-Identifier: GPL-3.0-or-later
##
## -*- texinfo -*-
## @deftypefn {} {@var{out} =} des_blockcrypt (@var{block}, @var{key}, @var{direction}, @var{variant}, @var{custom})
## Encrypt or decrypt one 8-byte DES block.
##
## @var{direction} is 1/"encrypt" or 0/"decrypt".  @var{variant} is
## "standard" (FIPS 46-3), "qqmusic" (private bit order used by QRC), a
## function handle, a callback struct, or a name registered with
## @code{des_register_variant}.
##
## Custom logic receives @code{(block, key, direction)} and must return
## 8 bytes.  A callback struct may provide @code{encrypt}, @code{decrypt}
## and/or a single @code{apply} handle.  The optional fifth argument
## @var{custom} overrides @var{variant} when supplied.
## @end deftypefn
function out = des_blockcrypt (block, key, direction, variant = 'standard', custom = [])
  des_init ();
  if (nargin < 3)
    print_usage ();
  endif

  dir = des_direction (direction);
  cb = [];
  source = variant;
  if (nargin >= 5 && ! isempty (custom))
    source = custom;
  endif

  if (isa (source, 'function_handle'))
    cb = source;
  elseif (isstruct (source))
    cb = source;
  elseif (ischar (source) || isa (source, 'string'))
    name = char (source);
    named = des_variant_registry ('get', name);
    if (! isempty (named))
      cb = named;
    else
      variant = name;
    endif
  else
    error ('des_blockcrypt: variant must be a string, function handle or callback struct');
  endif

  if (isempty (cb))
    out = des_blockcrypt_core (block, key, dir, variant);
    return;
  endif

  out = des_apply_custom (cb, block, key, dir);
  out = des_check_block (out);
endfunction

function dir = des_direction (d)
  if (ischar (d) || isa (d, 'string'))
    s = char (d);
    if (strcmp (s, 'encrypt') || strcmp (s, 'E') || strcmp (s, 'e'))
      dir = 1;
    elseif (strcmp (s, 'decrypt') || strcmp (s, 'D') || strcmp (s, 'd'))
      dir = 0;
    else
      error ('des_blockcrypt: unknown direction "%s"', s);
    endif
  elseif (isnumeric (d) || islogical (d))
    v = double (d);
    if (numel (v) != 1 || (v != 0 && v != 1))
      error ('des_blockcrypt: direction must be 0 or 1');
    endif
    dir = v;
  else
    error ('des_blockcrypt: direction must be numeric or a string');
  endif
endfunction

function out = des_apply_custom (cb, block, key, dir)
  if (isa (cb, 'function_handle'))
    out = feval (cb, block, key, dir);
    return;
  endif
  if (! isstruct (cb))
    error ('des_blockcrypt: callback must be a function handle or struct');
  endif
  if (isfield (cb, 'apply'))
    out = feval (cb.apply, block, key, dir);
  elseif (dir == 1 && isfield (cb, 'encrypt'))
    out = feval (cb.encrypt, block, key, 1);
  elseif (dir == 0 && isfield (cb, 'decrypt'))
    out = feval (cb.decrypt, block, key, 0);
  else
    error ('des_blockcrypt: callback struct has no handler for this direction');
  endif
endfunction

function out = des_check_block (out)
  if (! isnumeric (out) || numel (out) != 8)
    error ('des_blockcrypt: custom logic must return exactly 8 bytes');
  endif
  v = double (out(:));
  if (any (v < 0) || any (v > 255) || any (v != fix (v)))
    error ('des_blockcrypt: custom logic returned bytes outside [0,255]');
  endif
  out = reshape (uint8 (v), 1, 8);
endfunction
