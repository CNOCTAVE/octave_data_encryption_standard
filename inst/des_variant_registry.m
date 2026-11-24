## Copyright (C) 2026 Yu Hongbo <yuhongbo@member.fsf.org>, CNOCTAVE
## SPDX-License-Identifier: GPL-3.0-or-later
## Internal registry for named custom des_blockcrypt variants.
function varargout = des_variant_registry (action, name, encrypt_fn, decrypt_fn)
  persistent names
  persistent encrypts
  persistent decrypts
  if (isempty (names))
    names = {};
    encrypts = {};
    decrypts = {};
  endif

  varargout = cell (1, nargout);
  switch (action)
    case 'register'
      idx = des_variant_index (names, name);
      if (idx == 0)
        names{end+1} = name;
        encrypts{end+1} = encrypt_fn;
        decrypts{end+1} = decrypt_fn;
      else
        encrypts{idx} = encrypt_fn;
        decrypts{idx} = decrypt_fn;
      endif
    case 'unregister'
      idx = des_variant_index (names, name);
      if (idx != 0)
        names(idx) = [];
        encrypts(idx) = [];
        decrypts(idx) = [];
      endif
    case 'get'
      idx = des_variant_index (names, name);
      cb = [];
      if (idx != 0)
        cb = struct ('name', name, 'encrypt', encrypts{idx}, 'decrypt', decrypts{idx});
      endif
      varargout{1} = cb;
    case 'list'
      varargout{1} = names;
    otherwise
      error ('des_variant_registry: unknown action %s', action);
  endswitch
endfunction

function idx = des_variant_index (names, name)
  idx = 0;
  for i = 1:numel (names)
    if (strcmp (names{i}, name))
      idx = i;
      return;
    endif
  endfor
endfunction
