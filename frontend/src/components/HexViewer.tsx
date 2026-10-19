import React from 'react';

interface HexViewerProps {
  hexString: string;
  bytesPerRow?: number;
}

export const HexViewer: React.FC<HexViewerProps> = ({ hexString, bytesPerRow = 16 }) => {
  // Clean whitespace from hex string
  const cleanHex = hexString.replace(/\s+/g, '');

  if (!cleanHex) {
    return <div className="text-xs text-slate-500 italic p-2">No hex excerpt available.</div>;
  }

  // Parse bytes
  const bytes: number[] = [];
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes.push(parseInt(cleanHex.substring(i, i + 2), 16));
  }

  // Group into rows
  const rows: { offset: number; hex: string[]; ascii: string }[] = [];
  for (let r = 0; r < bytes.length; r += bytesPerRow) {
    const chunk = bytes.slice(r, r + bytesPerRow);
    const hexParts = chunk.map((b) => b.toString(16).padStart(2, '0'));
    const ascii = chunk
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');
    rows.push({
      offset: r,
      hex: hexParts,
      ascii,
    });
  }

  return (
    <div className="font-mono text-xs bg-slate-950 p-3 rounded-lg border border-slate-800 overflow-x-auto shadow-inner">
      <div className="space-y-1 select-text">
        {rows.map((row) => (
          <div key={row.offset} className="flex gap-4 items-center hover:bg-slate-900/60 px-1 rounded">
            {/* Offset */}
            <span className="text-slate-500 select-none w-14">
              {row.offset.toString(16).padStart(4, '0')}
            </span>

            {/* Hex Bytes */}
            <div className="flex gap-1.5 w-80 text-sky-300">
              {row.hex.map((h, idx) => (
                <span
                  key={idx}
                  className={idx === 7 ? 'mr-2 font-semibold' : 'font-normal'}
                >
                  {h}
                </span>
              ))}
            </div>

            {/* ASCII Column */}
            <span className="text-amber-300/80 tracking-widest pl-2 border-l border-slate-800">
              {row.ascii}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
};
