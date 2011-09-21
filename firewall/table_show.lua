
local function table_show(t, name, indent, plist)
  local cart    -- a container
  local autoref  -- for self references

  local function isemptytable(t) return next(t) == nil end

  local function gettablebvals(t, saved)
    local function isshort(list, max, line, saved)
      local n = #list
      local expand = false

      local c = ""

      if n > max then
        return false
      end

      for i, tu in ipairs(list) do
        if #c > line then
          expand = true
          break
        end

        local k, v = tu.key, tu.value
        if type(v) == "function" or saved[tu.value] then
          expand = true
          break
        elseif type(v) == "table" then
          local l = gettablebvals(v, saved)
          local short, nc = isshort(l, max - n, line - #c, saved)
          if not short then
            expand = true
            break
          end
          c = c .. nc
        else
          if type(k) == "number" then
            c = c .. string.format("%q", k, v)
          else
            c = c .. string.format("[%q] = %q", k, v)
          end
        end

        if #c > line then
          expand = true
          break
        end
      end
      return not expand, c
    end

    local ret = {}
    local tag

    if t.tag then
      for k, v in pairs(t) do
        if k == "tag" then
        else
          table.insert(ret, {key = k, value = v})
        end
      end
    else
      for k, v in pairs(t) do
        table.insert(ret, {key = k, value = v})
      end
    end
    return ret, isemptytable(t), isshort(ret, 7, 40, saved), t.tag
  end


  local function basicSerialize (o, quote)
    local so = tostring(o)
    if type(o) == "function" then
      local info = debug.getinfo(o, "S")
      -- info.name is nil because o is not a calling level
      if info.what == "C" then
        return string.format("%q", so .. ", C function")
      else 
        -- the information is defined through lines
        return string.format("%q", so .. ", defined in (" ..
           info.linedefined .. "-" .. info.lastlinedefined ..
           ")" .. info.source)
      end
    elseif type(o) == "number" then
      return so
    --[[elseif type(o) == "string" then
      if quote or not string.match(o, "^[a-z_]+$") then
        return string.format("%q", so)
      else
        return string.format("%q", so), o
      end]]
    else
      return string.format("%q", so)
    end
  end

  local function addtocart (value, name, indent, saved, field)
    indent = indent or ""
    saved = saved or {}

    if not field then
      if field == nil then
        field = name
      end
    end

    if field then
      cart = cart .. indent .. field
    else
      cart = cart .. indent
    end

    if type(value) ~= "table" then
      if field then
        cart = cart .. " = " .. basicSerialize(value, true) .. ";"
      else
        cart = cart .. basicSerialize(value, true) .. ";"
      end
    else
      if saved[value] then
        local v = saved[value]
        if type(v) == "string" then
          if field then
            cart = cart .. " = {}; -- " .. saved[value] .. " (self reference)"
          else
            cart = cart .. "{}; -- " .. saved[value] .. " (self reference)"
          end
          autoref = autoref ..  name .. " = " .. saved[value] .. ";\n"
        elseif type(v) == "table" then
          if field then
            cart = cart .. " = " .. v.value .. ";"
          else
            cart = cart .. v.value .. ";"
          end
        end
      else
        saved[value] = name

        local list, empty, short, tag = gettablebvals(value, saved)

        if field then
          cart = cart .. " = "
        end

        if tag then
          cart = cart .. tag .. " "
        end

        if empty then
          cart = cart .. "{};"
        --[=[elseif false and value.tag then
          if value.tag == "token" then
            cart = cart .. string.format(" = [1;32m%s<[1;31m%s[1;32m>[0;m%s\n", value.tag, value.value,
              --table.concat({" (id:", value.id, ", line:", value._line,")"})
              ""
              )
          elseif value.repr then
            cart = cart .. string.format(" = [[[1;34m%s[0;m]]\n", value:repr(indent))
          else
            if value.kind then
              cart = cart .. string.format(" = [1;33m%s[0;m:[1;35m%s[0;m {\n", value.tag, value.kind)
            else
              cart = cart .. string.format(" = [1;33m%s[0;m {\n", value.tag)
            end
            for k, v in pairs(value) do
              if k ~= "tag" and k ~= "kind" then
                if type(k) == "string" and string.byte(k, 1) == 95 then
                else
                  local k, f = basicSerialize(k, false)
                  local fname = string.format("%s[%s]", name, k)
                  if f then
                    field = string.format("%s", f)
                  else
                    field = string.format("[%s]", k)
                  end
                  addtocart(v, fname, indent .. "  ", saved, field)
                  cart = cart .. "\n"
                end
              end
            end
            cart = cart .. indent .. "};"
          end]=]
        else
          if short then
            cart = cart .. "{"
          else
            cart = cart .. "{\n"
          end

          for i, tu in ipairs(list) do
            local fname
            local k, f = basicSerialize(tu.key)
            local fname = string.format("%s[%s]", name, k)
            if type(tu.key) == "number" then
              field = false
            else
              field = string.format("[%s]", k)
              if f then
                field = string.format("%s", f)
              else
                field = string.format("[%s]", k)
              end
            end
            if short then
              addtocart(tu.value, fname, " ", saved, field)
            else
              addtocart(tu.value, fname, indent .. "  ", saved, field)
              cart = cart .. "\n"
            end
          end
          if short then
            cart = cart .. " };"
          else
            cart = cart .. indent .. "};"
          end
        end
      end
    end
  end

  name = name or "__unnamed__"
  if type(t) ~= "table" then
    return name .. " = " .. basicSerialize(t) .. "\n"
  end
  cart, autoref = "", ""
  addtocart(t, name, indent, plist) 
  return cart .. "\n" .. autoref
end

--[[print(table_show({
  {2, 3, 4, {}}
}))]]

return table_show
