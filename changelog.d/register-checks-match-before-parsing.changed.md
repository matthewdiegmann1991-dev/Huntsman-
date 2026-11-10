- The sanctions lists and the AEC returns kept on the device are matched before they are
  parsed: every row or block is asked whether it can carry each word of the name (or a
  number's digits) in place, without splitting or allocating, and only a listing that can is
  built from its rows; a table none of whose columns is looked in is counted alone, and a copy
  that is UTF-8 becomes text without being copied. A people or company lookup finds the same
  listings for less: against the live copies (release build, one x86 core) the OFAC list took
  92 ms and takes 41, the UN list 33 and 13, the EU list 333 and 158 (its peak memory 88 MB
  and 68), the AEC archive 220 and 105; DFAT's workbook, decoded whole, is unchanged.
