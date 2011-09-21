-- generates node maps to help me play keyboard...

local function Class(name, meta, construct)
  meta.__index = meta
  meta["@tag"] = name

  return setmetatable(
    meta,
    { __call = construct}
  )
end

local function scale_n(scale, derriv, n)
  local new = {}
  local name = {}
  local west = {}
  local start = scale.start;
  local dntab = {
    ["c"] = "ces";
    ["d"] = "des";
    ["e"] = "es";
    ["f"] = "fes";
    ["g"] = "ges";
    ["a"] = "as";
    ["h"] = "b";
  }
  steps = derriv.row;
  local base = (scale.base + n) % 12
  for k = 0, 6, 1 do
    west[scale.key[k]] = scale.name[k]
    new[k] = (base + steps[k]) % 12;
    --print(string.format("ROW %d = %d <- %d", k, new[k], steps[k]))
  end
  for k = 0, 6, 1 do
    --print(k, new[k], scale.base, base, scale.start)
    if new[k] == scale.base then
      local key = {}
      for j = 0, 6, 1 do
        key[j] = new[(k + start + j) % 7]
        if n > 0 then
          name[j] = west[key[j]] or scale.name[(7 - start + k) %7] .. "is"
        else
          --print(start, k)
          --name[j] = west[key[j]] or assert(dntab[scale.name[(7 - start + k) %7]])
          name[j] = west[key[j]] or dntab[scale.name[(7 - start + k + 2) % 7]]
        end
        --print(string.format("KEY %d = %d (%s) (was %d)", j, key[j], name[j], scale.key[j]))
      end
      return {
        base = base;
        row = new;
        name = name;
        key = key;
        start = (k + scale.start) % 7;
        shift = k;
      }
    end
  end
  assert(false, "failure")
end

local function scale_print(scale, derriv)
  local prn = {}
  local name = scale.name;
  local k = scale.start;
  local key = scale.key;
  prn[#prn + 1] = string.format("[%3s (%2d,%2d, %2d)]:",
      name[(-k) % 7]:upper(), scale.base, scale.start, scale.shift)
  --k = 0;
  for j = 0, 6, 1 do
    local id = (j - k) % 7
    if derriv then
      prn[#prn + 1] = string.format("%3s(%2d/%2d)", name[id], key[id], derriv.key[id])
    else
      prn[#prn + 1] = string.format("%3s(%2d)", name[id], key[id])
    end
  end
  print(table.concat(prn, " "))
end

local scales = {}
scales["C"] = {
  base = 0;
  row = {[0] = 0; [1] = 2; [2] = 4; [3] = 5; [4] = 7; [5] = 9; [6] = 11;};
  key = {[0] = 0; [1] = 2; [2] = 4; [3] = 5; [4] = 7; [5] = 9; [6] = 11;};
  name = {[0] = "c", [1] = "d", [2] = "e", [3] = "f", [4] = "g", [5] = "a", [6] = "h"};
  start = 0;
  shift = 0;
}
--scale_print(scales["C"])
scales["F"] = scale_n(scales["C"], scales["C"], -7)
scales["B"] = scale_n(scales["F"], scales["C"], -7)
scales["ES"] = scale_n(scales["B"], scales["C"], -7)
scales["AS"] = scale_n(scales["ES"], scales["C"], -7)
scales["DES"] = scale_n(scales["AS"], scales["C"], -7)
scales["GES"] = scale_n(scales["DES"], scales["C"], -7)
scales["CES"] = scale_n(scales["GES"], scales["C"], -7)
scales["G"] = scale_n(scales["C"], scales["C"], 7)
scales["D"] = scale_n(scales["G"], scales["C"], 7)
scales["A"] = scale_n(scales["D"], scales["C"], 7)
scales["E"] = scale_n(scales["A"], scales["C"], 7)
scales["H"] = scale_n(scales["E"], scales["C"], 7)
scales["FIS"] = scale_n(scales["H"], scales["C"], 7)
scales["CIS"] = scale_n(scales["FIS"], scales["C"], 7)


Note = Class("Note", {
  get_pos = function(self)
    return self.pos
  end;
  get_key = function(self)
    return (self.scale.key[self.pos % 7] + self.add) % 12
  end;
  get_name = function(self)
    return self.scale.name[self.pos % 7]
  end;
},
function(meta, scale, pos, add)
  local self = {
    scale = scale;
    pos = pos;
    add = add or 0;
  }
  return setmetatable(self, meta)
end)

NoteView = Class("NoteView", {
  draw = function(self, cr, x, y)
    local grid = self.grid
    cr:save();
    cr:rectangle(x, y, 6 * grid, 39 * grid)
    cr:clip();
    cr:set_source_rgb(0, 0, 0)
    -- lines
    do
      cr:set_source_rgb(.8, .8, .8)
      cr:rectangle(x, y + 15 * grid, 6 * grid, 8 * grid)
      cr:fill()
      cr:set_source_rgb(0, 0, 0)
      cr:set_line_width(1.5)
      for k = 0, 9, 2 do
        cr:move_to(x, y + (23 - k) * grid)
        cr:rel_line_to(6 * grid, 0)
        cr:stroke()
      end
    end
    local pos = self.note:get_pos() + self.clef
    if (pos >= -12) and (pos <=24) then
      -- extra lines
      cr:set_line_width(1)
      do
        if pos <= 0 then
          for k = 0, pos, -2 do
            local apos = (25 - k);
            cr:move_to(x + 1 * grid, y + apos * grid)
            cr:rel_line_to(4 * grid, 0)
            cr:stroke()
          end
        end
        if pos >= 12 then
          for k = 12, pos, 2 do
            local apos = (25 - k);
            cr:move_to(x + 1 * grid, y + apos * grid)
            cr:rel_line_to(4 * grid, 0)
            cr:stroke()
          end
        end
      end
      -- note
      do
        local nx, ny = x + 3 * grid, y + (25 - pos) * grid
        cr:move_to(nx - 1 * grid, ny)
        cr:rel_curve_to(0, 1.5 * grid, 2 * grid, 1 * grid, 2 * grid, 0)
        cr:rel_curve_to(0, -1.5 * grid, -2 * grid, -1 * grid, -2 * grid, 0)
        cr:close_path()
        cr:fill();
      end
    end
    cr:restore();
  end;
},
function(meta, note, clef)
  local self = {
    note = note;
    grid = 5;
    clef = clef;
  }
  return setmetatable(self, meta)
end)

Board = Class("Board", {
  draw = function(self, cr, x, y)
    local grid = self.grid
    local key = self.note:get_key()
    local function select_color(cr, key, remap, num)
      local sel = num
      if remap then
        local map = {[0] = 0; [1] = 2; [2] = 4; [3] = 5; [4] = 7; [5] = 9; [6] = 11;}
        sel = map[num]
      end
      local function white(cr)
        cr:set_source_rgb(1, 1, 1)
        cr:fill_preserve()
        cr:set_source_rgb(0, 0, 0)
        cr:stroke()
      end
      local function white_sel(cr)
        cr:set_source_rgb(1, 0, 0)
        cr:fill_preserve()
        cr:set_source_rgb(0, 0, 0)
        cr:stroke()
      end
      local function black(cr)
        cr:set_source_rgb(0, 0, 0)
        cr:fill()
      end
      local function black_sel(cr)
        cr:set_source_rgb(1, 0, 0)
        cr:fill_preserve()
        cr:set_source_rgb(0, 0, 0)
        cr:stroke()
      end
      local select = {
        [0]  = {[false] = white; [true] = white_sel;};
        [1]  = {[false] = black; [true] = black_sel;};
        [2]  = {[false] = white; [true] = white_sel;};
        [3]  = {[false] = black; [true] = black_sel;};
        [4]  = {[false] = white; [true] = white_sel;};
        [5]  = {[false] = white; [true] = white_sel;};
        [6]  = {[false] = black; [true] = black_sel;};
        [7]  = {[false] = white; [true] = white_sel;};
        [8]  = {[false] = black; [true] = black_sel;};
        [9]  = {[false] = white; [true] = white_sel;};
        [10] = {[false] = black; [true] = black_sel;};
        [11] = {[false] = white; [true] = white_sel;};
      }
      select[sel][sel == key](cr)
    end
    cr:save()
    cr:set_line_width(1.5)
    for k = 0, 6, 1 do
      cr:move_to(x + grid * k * 2, y)
      cr:rel_line_to(0, 13 * grid)
      cr:rel_line_to(2 * grid, 0)
      cr:rel_line_to(0, -13 * grid)
      cr:close_path()
      select_color(cr, key, true, k)
    end
    do
      cr:move_to(x + grid, y)
      cr:rel_line_to(0, 9 * grid)
      cr:rel_line_to(1.5 * grid, 0)
      cr:rel_line_to(0, -9 * grid)
      cr:close_path()
      select_color(cr, key, false, 1)
    end
    do
      cr:move_to(x + grid * 5, y)
      cr:rel_line_to(0, 9 * grid)
      cr:rel_line_to(-1.5 * grid, 0)
      cr:rel_line_to(0, -9 * grid)
      cr:close_path()
      select_color(cr, key, false, 3)
    end
    do
      cr:move_to(x + grid * 7, y)
      cr:rel_line_to(0, 9 * grid)
      cr:rel_line_to(1.5 * grid, 0)
      cr:rel_line_to(0, -9 * grid)
      cr:close_path()
      select_color(cr, key, false, 6)
    end
    do
      cr:move_to(x + grid * 9.25, y)
      cr:rel_line_to(0, 9 * grid)
      cr:rel_line_to(1.5 * grid, 0)
      cr:rel_line_to(0, -9 * grid)
      cr:close_path()
      select_color(cr, key, false, 8)
    end
    do
      cr:move_to(x + grid * 13, y)
      cr:rel_line_to(0, 9 * grid)
      cr:rel_line_to(-1.5 * grid, 0)
      cr:rel_line_to(0, -9 * grid)
      cr:close_path()
      select_color(cr, key, false, 10)
    end
    cr:restore()
  end;
},
function(meta, note)
  local self = {
    note = note;
    grid = 5;
  }
  return setmetatable(self, meta)
end)

Pack = Class("Pack", {
  draw = function(self, cr, x, y)
    local grid = self.grid
    cr:save()
    cr:move_to(x + 7 * grid, y)
    cr:rel_line_to(0, 39 * grid)
    cr:stroke()
    self.vclef:draw(cr, x, y)
    self.bclef:draw(cr, x + 8 * grid, y)
    self.board:draw(cr, x, y + 39 * grid)
    cr:set_font_size(20)
    cr:select_font_face("Monospace", "normal", "normal")
    local te = cr:text_extents(self.note:get_name())
    if self.note:get_pos() >= 0 then
      cr:rectangle(x + 7 * grid - te.width, y + 33 * grid - te.height*4/3, te.width*2, te.height*2)
      cr:set_source_rgb(1, 1, 1)
      cr:fill();
      cr:move_to(x + 7 * grid - te.width/2, y + 33 * grid)
    else
      cr:rectangle(x + 7 * grid - te.width, y + 9 * grid - te.height*4/3, te.width*2, te.height*2)
      cr:set_source_rgb(1, 1, 1)
      cr:fill();
      cr:move_to(x + 7 * grid - te.width/2, y + 9 * grid)
    end
    cr:set_source_rgb(0, 0, 0)
    cr:show_text(self.note:get_name())
    cr:set_source_rgb(0, 0, 0)
    cr:set_line_width(2)
    cr:rectangle(x, y, 14 * grid, (39 + 13) * grid)
    cr:stroke()
    cr:restore()
  end;
},
function(meta, note)
  local self = {
    note = note;
    vclef = NoteView(note, 0);
    bclef = NoteView(note, 12);
    board = Board(note);
    grid = 5;
  }
  return setmetatable(self, meta)
end)

local cairo = require "oocairo"

local image = cairo.pdf_surface_create("map.pdf", 15 * 5 * 23, (39 + 13) * 5 * 2)
local cr = cairo.context_create(image)

-- main
local sc = scales["E"]
for k = 0, 20, 1 do
  Pack(Note(sc, k - 21)):draw(cr, 15 * 5 + 15 * 5 * k, 0)
end
for k = 0, 20, 1 do
  Pack(Note(sc, k)):draw(cr, 15 * 5 + 15 * 5 * k, (39 + 13 + 1) * 5)
end