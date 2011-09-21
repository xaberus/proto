#!/usr/bin/lua

local ipt_parse = dofile("ipt.gram.lua")
local table_show = dofile("table_show.lua")

local function ipt_command(fam)
  if fam == 4 then
    --return string.format("ip%stables-save -c", "", "4")
    return string.format("ip%stables-save ", "", "4")
  elseif fam == 6 then
    return string.format("ip%stables-save -c", "6")
  else
    return nil
  end
end

local function read_config(config)
  local f = assert(loadfile(config))
  local env = {}

  local tags = {
    'uchains',
    'uchain',
    'dchains',
    'dchain',
    'rules',
    'commalist',
    'slashlist',
    'colonlist',
    'target'
  }

  for k, tag in ipairs(tags) do
    env[tag] = function(tbl)
      tbl.tag = tag
      return tbl
    end
  end

  setfenv(f, env)

  f()

  return env
end

local function ipt_cleanup(config, saved)
  local iptables = {}
  for k, itbl in ipairs(saved) do
    local dchains = setmetatable({}, { __index = config.targets })

    local tbl = {}

    for i, dc in ipairs(itbl.dchains) do
      dchains[dc.name] = dc
      dc.rules = {}
      -- dc.table = tbl
      dc.policy = dchains[dc.policy]
    end

    local chain
    local chains = {}
    -- do not stain the namespace
    setmetatable(chains, { __index = dchains })

    tbl.dchains = dchains
    tbl.chains = chains
    tbl.name = itbl.name

    iptables[itbl.name] = tbl

    for j, rule in ipairs(itbl.rules) do
      --print(table_show(rule, "rule"))

      local cname
      local rl = {}
      for m, part in pairs(rule) do
        if part["chain"] then
          cname = part.chain
        elseif part["jump"] then
          local tname = assert(part["jump"].target)
          local target = chains[tname]
          if not target then
            target = {}
            target["name"]       = assert(tname)
            --target["table"]      = tbl
            target["rules"]      = {}
            chains[tname] = target
          end
          rl.jump = part["jump"]
          rl.jump.target = target
        else
          if type(m) == "number" then
            table.insert(rl, part)
          else
            rl[m] = part
          end
        end
      end
      rule = rl

      chain = chains[cname]
      if not chain or not chain.name then
        if not chain then
          chain = {}
          chains[cname] = chain
        end
        chain["name"]       = assert(cname)
        --chain["table"]      = tbl
        chain["rules"]      = {}
      end

      --rule.chain = chain

      table.insert(chain.rules, rule)
    end
  end

  return iptables
end

--print(table_show(ipt_config, "ipt_config"))

local function ipt_print(config)
  iptables = config.tables

  local function table_handle(tbl)
    local tag = tbl.tag

    if not tag then
      return nil
    end

    if tag == "slashlist" then
      return table.concat(tbl, "/")
    elseif tag == "dotlist" then
      return table.concat(tbl, ".")
    elseif tag == "colonlist" then
      return table.concat(tbl, ":")
    elseif tag == "commalist" then
      return table.concat(tbl, ",")
    end
  end

  local function ipt(cmd)
    print("iptables " .. cmd)
  end

  local function print_rule(tbl, chain, rule, saved)
    if not saved[rule] then
      local rl = string.format("-t %s -A %s", tbl.name, chain.name)
      for m, part in ipairs(rule) do
        if part["chain"] then
        elseif part["source"] then
          local tbl = part["source"]
          local res = table_handle({tag = tbl.tag, tbl.ip4, tbl.ip4mask})
          rl = rl .. " -s " .. res
        elseif part["destination"] then
          local tbl = part["destination"]
          local res = table_handle({tag = tbl.tag, tbl.ip4, tbl.ip4mask})
          if res then
            rl = rl .. " -d " .. res
          end
        elseif part["jump"] then
          local tbl = part["jump"]
          rl = rl .. " -j " .. tbl.target
          if tbl.options then
            for opt, val in pairs(tbl.options) do
              rl = rl .. " --" .. opt .. " " .. val
            end
          end
        elseif part["protocol"] then
          rl = rl .. " -p " .. part["protocol"]
        elseif part["in-interface"] then
          rl = rl .. " -i " .. part["in-interface"]
        elseif part["out-interface"] then
          rl = rl .. " -o " .. part["out-interface"]
        elseif part["match"] then
          local match = part["match"]
          for mname, mvalue in pairs(match) do
            rl = rl .. " -m " .. mname
            if mname == "tcp" then
              for opt, val in pairs(mvalue) do
                if type(val) == "string" then
                  rl = rl .. " --" .. opt .. " " .. val
                elseif opt == "tcp-flags" then
                  local res1 = table_handle(val.mask)
                  local res2 = table_handle(val.comp)
                  rl = rl .. " --" .. opt .. " " .. res1 .. " " .. res2
                else
                  local res = table_handle(val)
                  rl = rl .. " --" .. opt .. " " .. res
                end
              end
            else
              for opt, val in pairs(mvalue) do
                if type(val) == "string" then
                  rl = rl .. " --" .. opt .. " " .. val
                else
                  local res = table_handle(val)
                  rl = rl .. " --" .. opt .. " " .. res
                end
              end
            end
          end
        else
          --assert(false)
        end
      end

      if rule.stats then
        rl = rl .. string.format(" -c %s %s", rule.stats.packets, rule.stats.bytes)
      end

      do
        local tbl = rule.jump
        rl = rl .. " -j " .. tbl.target.name
        if tbl.options then
           for opt, val in pairs(tbl.options) do
           rl = rl .. " --" .. opt .. " " .. val
           end
        end
      end

      rl = rl .. " "

      return rl
    end
  end

  local targets = config.targets

  local function print_chain(tbl, chain, saved)
    if not saved[chain] then
      saved[chain] = true
      local chainname = assert(chain.name)

      if not targets[chainname] then
        if tbl.dchains[chainname] then
          ipt(string.format("-t %s -F %s", tbl.name, chainname))
          if chain.policy then
            ipt(string.format("-t %s -P %s %s", tbl.name, chainname, chain.policy.name))
          end
        else
          ipt(string.format("-t %s -N %s", tbl.name, chainname))
        end
        for n, rule in ipairs(chain.rules) do
          if not saved[rule.jump.target] then
            print_chain(tbl, rule.jump.target, saved)
          end
          ipt(print_rule(tbl, chain, rule, saved))
        end
      end
    end
  end

  for tblname, tbl in pairs(iptables) do
    ipt(string.format("-t %s -F", tbl.name))
    ipt(string.format("-t %s -X", tbl.name))

    local saved = {}
    for chainname, chain in pairs(tbl.chains) do
      print_chain(tbl, chain, saved)
    end
    for chainname, chain in pairs(tbl.dchains) do
      print_chain(tbl, chain, saved)
    end
  end
end

local function tbl2dot(tbl)
  local inner = {}
  local attrs = {}

  if tbl.tag == "table" then
    tbl.cellborder = 1
    tbl.cellspacing = 0
    tbl.cellpadding = 0
    tbl.border = 0
  end

  for k, v in pairs(tbl) do
    if type(k) == "number" then
      if type(v) == "table" then
        table.insert(inner, tbl2dot(v))
      else
        table.insert(inner, v)
      end
    elseif k == "tag" then
    else
      table.insert(attrs, string.format("%s=%q", k, tostring(v)))
    end
  end

  local ret = string.format("<%s %s>%s</%s>", tbl.tag,
    table.concat(attrs, " "), table.concat(inner, ""), tbl.tag)

  return ret
end

local function ipt_dot(config, dotfile)
  local fd = io.open(dotfile, "w")
  local function write(...)
    fd:write(string.format(...))
  end

  write("digraph trie {\n")

  write("  graph [rankdir = TD];\n")
  write("  node [fontsize = 12, fontname = \"monospace\"];\n")
  write("  edge [];\n")

  local function dtable(tbl) tbl.tag = "table"; return tbl; end
  local function dtr(tbl) tbl.tag = "tr"; return tbl; end
  local function dtd(tbl) tbl.tag = "td"; return tbl; end

  local function dnode(name, tbl)
    write("  %q [shape = plaintext, label = <%s>];\n", name, tbl2dot(tbl))
  end
  local function dedge(src, fs, dst, fd, label, color)
    write("  ")
    if fs then
      write("%q:%s", src, fs)
    else
      write("%q", src)
    end
    write(" -> ")
    if fd then
      write("%q:%s", dst, fd)
    else
      write("%q", dst)
    end

    write("[")

    if label then
      write(" label=%q ", label)
    end
    if color then
      write(" color=%q ", color)
    end

    write("];\n")
  end

  local function table_handle(tbl)
    local tag = tbl.tag

    if not tag then
      return nil
    end

    if tag == "slashlist" then
      return table.concat(tbl, "/")
    elseif tag == "dotlist" then
      return table.concat(tbl, ".")
    elseif tag == "colonlist" then
      return table.concat(tbl, ":")
    elseif tag == "commalist" then
      return table.concat(tbl, ",")
    end
  end

  local function ipt(cmd)
    print("iptables " .. cmd)
  end


  local function print_rule(tbl, chain, rule)
    if true then
      local rl = ""
      for m, part in ipairs(rule) do
        if part["chain"] then
        elseif part["source"] then
          local tbl = part["source"]
          local res = table_handle({tag = tbl.tag, tbl.ip4, tbl.ip4mask})
          rl = rl .. " -s " .. res
        elseif part["destination"] then
          local tbl = part["destination"]
          local res = table_handle({tag = tbl.tag, tbl.ip4, tbl.ip4mask})
          if res then
            rl = rl .. " -d " .. res
          end
        elseif part["jump"] then
          local tbl = part["jump"]
          rl = rl .. " -j " .. tbl.target
          if tbl.options then
            for opt, val in pairs(tbl.options) do
              rl = rl .. " --" .. opt .. " " .. val
            end
          end
        elseif part["protocol"] then
          rl = rl .. " -p " .. part["protocol"]
        elseif part["in-interface"] then
          rl = rl .. " -i " .. part["in-interface"]
        elseif part["out-interface"] then
          rl = rl .. " -o " .. part["out-interface"]
        elseif part["match"] then
          local match = part["match"]
          for mname, mvalue in pairs(match) do
            rl = rl .. " -m " .. mname
            if mname == "tcp" then
              for opt, val in pairs(mvalue) do
                if type(val) == "string" then
                  rl = rl .. " --" .. opt .. " " .. val
                elseif opt == "tcp-flags" then
                  local res1 = table_handle(val.mask)
                  local res2 = table_handle(val.comp)
                  rl = rl .. " --" .. opt .. " " .. res1 .. " " .. res2
                else
                  local res = table_handle(val)
                  rl = rl .. " --" .. opt .. " " .. res
                end
              end
            else
              for opt, val in pairs(mvalue) do
                if type(val) == "string" then
                  rl = rl .. " --" .. opt .. " " .. val
                else
                  local res = table_handle(val)
                  rl = rl .. " --" .. opt .. " " .. res
                end
              end
            end
          end
        else
          --assert(false)
        end
      end

      if rule.stats then
        rl = rl .. string.format(" -c %s %s", rule.stats.packets, rule.stats.bytes)
      end

      --[[do
        local tbl = rule.jump
        rl = rl .. " -j " .. tbl.target.name
        if tbl.options then
           for opt, val in pairs(tbl.options) do
           rl = rl .. " --" .. opt .. " " .. val
           end
        end
      end]]

      return rl
    end
  end

  --write('  subgraph %q {\n', "cluster" .. tostring(config))
  dnode("iptables", dtable{dtr{dtd{"iptables"}}})
  --write('}\n')

  write('  { rank=same \n')
  for k, target in pairs(config.targets) do
    --write('  subgraph %q {\n', "cluster" .. tostring(target))
    local trnode = tostring(target)
    dnode(trnode, dtable{dtr{dtd{bgcolor = target.color, "target:" .. target.name}}})
  end
  write('};\n')

  write('  { rank=same \n')
  for k, tbl in pairs(config.tables) do
    local tnode = tostring(tbl)
    dnode(tnode, dtable{dtr{dtd{"table:" .. tbl.name}}})
  end
  write('};\n')

  for k, tbl in pairs(config.tables) do
    --write('  subgraph %q {\n', "cluster" .. tostring(tbl))
    local tnode = tostring(tbl)
    --write('  subgraph %q {\n', "cluster" .. tostring(config))
    --dnode(tnode, dtable{dtr{dtd{"table:" .. tbl.name}}})
    --write('}\n')
    dedge("iptables", nil, tnode, nil)

    write('  { rank=same \n')
    for l, chain in pairs(tbl.dchains) do
      local cnode = tostring(chain)
      write("%q;\n", cnode)
    end
    write('};\n')

    --[[write('  { rank=same \n')
    for l, chain in pairs(tbl.chains) do
      local cnode = tostring(chain)
      write("%q;\n", cnode)
    end
    write('};\n')]]


    for l, chain in pairs(tbl.dchains) do
      --write('subgraph %q {\n', "cluster" .. tostring(chain))
      local cnode = tostring(chain)
      local rules = dtable{dtr{dtd{m}, dtd{bgcolor = "gray", "chain:" .. chain.name}}}
      dnode(cnode, rules)
      dedge(tnode, nil, cnode, nil)

      local prev = cnode
      for m, rule  in ipairs(chain.rules) do
        local t = rule.jump.target
        local trnode = tostring(t)
        local rnode = tostring(rule)
        local show, info = print_rule(tbl, chain, rule)

        dnode(rnode, dtable{dtr{dtd{m}, dtd{show}}})
        dedge(rnode, tostring(m), trnode, nil, t.name, t.color)

        if prev then
          dedge(prev, nil, rnode, nil, nil, "blue")
        end

        prev = rnode
      end

      if chain.policy then
        dedge(prev, nil, tostring(chain.policy), nil, nil, "violet")
      end
      --write('}\n')
    end

    for l, chain in pairs(tbl.chains) do
      --write('subgraph %q {\n', "cluster" .. tostring(chain))
      local cnode = tostring(chain)
      local rules = dtable{dtr{dtd{m}, dtd{bgcolor = "yellow", "chain:" .. chain.name}}}
      dnode(cnode, rules)
      dedge(tnode, nil, cnode, nil)

      local prev = cnode
      for m, rule  in ipairs(chain.rules) do
        local t = rule.jump.target
        local trnode = tostring(t)
        local rnode = tostring(rule)
        local show, info = print_rule(tbl, chain, rule)

        dnode(rnode, dtable{dtr{dtd{m}, dtd{show}}})
        dedge(rnode, tostring(m), trnode, nil, t.name, t.color)

        if prev then
          dedge(prev, nil, rnode, nil, nil, "blue")
        end

        prev = rnode
      end
      --write('}\n')
    end
    --write('}\n')
  end

  write("}\n")

  fd:close()
end

local function reconfig(...)
  local args = {...}

  local cfgfile = "config.lua"
  local wfile = false
  local dotfile = false
  local ipt = false
  local imp = false

  for i, arg in ipairs(args) do
    do
      local res = arg:gmatch("^-c=(.*)$")()
      if res then
        cfgfile = res
      end
    end
    do
      local res = arg:gmatch("^-d=(.*)$")()
      if res then
        dotfile = res
      end
    end
    do
      local res = arg:gmatch("^-w=(.*)$")()
      if res then
        wfile = res
      end
    end
    do
      local res = arg:gmatch("^-I$")()
      if res then
        imp = true
      end
    end
    do
      local res = arg:gmatch("^-r$")()
      if res then
        ipt = true
      end
    end
    do
      local res = arg:gmatch("^-h$")()
      if res then
        print([[
usage:
  -c <cfg-file>   read config from file
  -d <dot-file>   write dot graph to file
  -w <cfg-file>   write config to file
  -I              import config from 'iptables-save'
  -h              this screen
]])
        os.exit(0)
      end
    end
  end

  local config = read_config(cfgfile).config
  local src = assert(io.popen(config.iptables_save):read("*a"))

  if not config.tables then
    imp = true
  end

  if imp then
    io.stderr:write("### importing rules ###\n")
    local saved = ipt_parse(src)
    local iptables = ipt_cleanup(config, saved)

    if wfile then
      --print(table_show(config, "config"))
      --print(table_show(iptables, "iptables"))

      wfile = assert(io.open(wfile, "w"))

      local function writeln(str)
        wfile:write(str .. "\n")
      end

      local plist = {}
      local function fu(plist, prefix)
          for k, v in pairs(plist) do
            if type(v) == "string" then
              if prefix then
                plist[k] = {value = prefix..v}
              else
                plist[k] = {value = v}
              end
            end
          end
      end

      local function pu(str)
        return string.format("[%q]", str)
      end

      writeln(table_show(config.targets, "targets", nil, plist)) fu(plist)

      local prefix = ""
      do

        local prefix = prefix .. "pre"
        writeln(string.format("%s = %s or {}\n", prefix, prefix))

        for k, tbl in pairs(iptables) do
          local targets = {}
          for l, chain in pairs(tbl.chains) do
            for m, rule in ipairs(chain.rules) do
              if not plist[rule.jump.target] then
                local s = targets[rule.jump.target]
                if not s then
                  s = {ref = 1}
                  targets[rule.jump.target] = s
                end
                s.ref = s.ref + 1
              end
            end
          end

          local prefix = prefix .. pu(tbl.name)
          writeln(string.format("%s = %s or {}\n", prefix, prefix))

          repeat
            local max = 0
            local chain
            for c, s in pairs(targets) do

              -- one of our targetsis out - emit immediately
              for m, rule in ipairs(c.rules) do
                if plist[rule.jump.target] then
                  local mu = targets[c]
                  mu.ref = mu.ref * 2
                end
              end

              --writeln("###", c.name, s.ref)
              if s.ref >= max then
                chain = c
                max = s.ref
              end
            end

            if chain then
              writeln(table_show(chain, prefix .. pu(chain.name), nil, plist)) fu(plist)
              targets[chain] = nil
            end

          until not next(targets)

          for l, chain in pairs(tbl.chains) do
            if not plist[chain] then
              writeln(table_show(chain, prefix .. pu(chain.name), nil, plist)) fu(plist)
            end
          end
          for l, chain in pairs(tbl.dchains) do
            writeln(table_show(chain, prefix .. pu(chain.name), nil, plist)) fu(plist)
          end
        end
      end

      --writeln(table_show(iptables, "tables", nilindent, plist)) fu(plist, prefix)

      writeln(table_show({
        family = config.family,
        iptables_save = config.iptables_save,
        iptables = config.iptables,
        targets = config.targets,
        tables = iptables,
      }, "config", nil, plist))

      wfile:close()
    end

    config.tables = iptables
  end

  if dotfile then
    ipt_dot(config, dotfile)
  end

  if ipt then
    ipt_print(config)
  end
end

reconfig(...)

