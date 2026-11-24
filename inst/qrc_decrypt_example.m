## Copyright (C) 2026 Yu Hongbo <yuhongbo@member.fsf.org>, CNOCTAVE
## SPDX-License-Identifier: GPL-3.0-or-later
##
## -*- texinfo -*-
## @deftypefn {} {@var{result} =} qrc_decrypt_example (@var{path})
## Minimal, copy-pasteable demonstration of the LyricTools.exe QRC pipeline.
## Returns a struct with @code{info}, @code{preview} (first 160 characters of
## the XML) and @code{has_qrc_header}.
## @end deftypefn
function result = qrc_decrypt_example (path)
  [xml, info] = qrc_decrypt_file (path);
  result = struct ('info', info, 'preview', '', 'has_qrc_header', false);
  if (! isempty (xml))
    result.preview = xml(1:min (160, numel (xml)));
    result.has_qrc_header = ! isempty (strfind (xml, '<QrcInfos>'));
  endif
endfunction
