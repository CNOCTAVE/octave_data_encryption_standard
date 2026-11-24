## Copyright (C) 2026 Yu Hongbo <yuhongbo@member.fsf.org>, CNOCTAVE
## SPDX-License-Identifier: GPL-3.0-or-later
##
## -*- texinfo -*-
## @deftypefn {} {[@var{xml}, @var{info}] =} qrc_decrypt_file (@var{path})
## Decrypt a LyricTools.exe @file{.qrc} file.
##
## Pipeline: 11-byte magic check -> 256-byte XOR pre-layer -> private 3DES-ECB
## -> zlib inflate -> UTF-8 XML.  @var{info} reports the file size, the body
## length, the magic bytes and the decompressed length.
## @end deftypefn
function [xml, info] = qrc_decrypt_file (path)
  des_init ();
  if (nargin < 1)
    print_usage ();
  endif
  fid = fopen (path, 'rb');
  if (fid == -1)
    error ('qrc_decrypt_file: cannot open %s', path);
  endif
  unwind_protect
    raw = fread (fid, Inf, 'uint8=>uint8');
  unwind_protect_cleanup
    fclose (fid);
  end_unwind_protect

  magic = reshape (uint8 ([0x98, 0x25, 0xb0, 0xac, 0xe3, 0x02, 0x83, 0x68, 0xe8, 0xfc, 0x6c]), 11, 1);
  ok = numel (raw) >= 11 && isequal (raw(1:11), magic);
  info = struct ('path', path, 'file_bytes', numel (raw), 'has_magic', ok, ...
                 'magic', '', 'body_bytes', max (0, numel (raw) - 11), ...
                 'xml_bytes', 0, 'method', 'XOR + 3DES-ECB(qqmusic) + zlib');
  if (ok)
    info.magic = upper (reshape (dec2hex (double (raw(1:11)), 2)', 1, []));
  endif
  if (! ok)
    xml = '';
    return;
  endif

  xml = qrc_raw_decrypt (path);
  info.xml_bytes = numel (xml);
endfunction
