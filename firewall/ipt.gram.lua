
local lpeg = require 'lpeg'
local P, R, S, C, Cc, Ct, Cg, Cb, Cp, Carg, V =
  lpeg.P, lpeg.R, lpeg.S, lpeg.C, lpeg.Cc, lpeg.Ct,
  lpeg.Cg, lpeg.Cb, lpeg.Cp, lpeg.Carg, lpeg.V

local g_ws = S" "

local g_underline = S "_-"
local g_upper_case = R("AZ")
local g_lower_case = R("az")
local g_digit = R("09")
local g_iden = ((g_upper_case + g_lower_case + g_underline + g_digit)^1 - P '-' - P '_')


local  g_string = (P '"' * (P(1) - P '"')^0 * P '"')

local g_table = V 'g_table'
local g_header = V 'g_header'
local g_name = V 'g_name'
local g_dchain = V 'g_dchain'
local g_uchain = V 'g_uchain'
local g_port = V 'g_port'
local g_rule = V 'g_rule'
local g_option = V 'g_option'
local g_stats = V 'g_stats'
local g_error = V 'g_error'
local g_rule_token = V 'g_rule_token'
local g_rule_start = V 'g_rule_start'
local g_rule_end = V 'g_rule_end'

local g_number = V 'g_number'
local g_chain = V 'g_chain'
local g_source = V 'g_source'
local g_destination = V 'g_destination'

local g_ip4_addr = V 'g_ip4_addr'
local g_ip4_addr_part = V 'g_ip4_addr_part'
local g_ip4_mask = V 'g_ip4_mask'

local g_sport = V 'g_sport'
local g_dport = V 'g_dport'

local g_jump = V 'g_jump'
local g_reject_opt = V 'g_reject_opt'
local g_nflog_opt = V 'g_nflog_opt'

local g_protocol = V 'g_protocol'
local g_in_interface = V 'g_in_interface'
local g_out_interface = V 'g_out_interface'

local g_match = V 'g_match'
local g_m_state = V 'g_m_state'

local g_m_limit = V 'g_m_limit'

local g_m_tcp = V 'g_m_tcp'
local g_tcp_flags = V 'g_tcp_flags'
local g_tcp_flags_opt = V 'g_tcp_flags_opt'

local g_m_udp = V 'g_m_udp'
local g_m_icmp = V 'g_m_icmp'
local g_m_owner = V 'g_m_owner'
local g_m_state_opt = V 'g_m_state_opt'

local g_long_opt = V 'g_long_opt'
local g_short_opt = V 'g_short_opt'

local g_footer = V 'g_footer'
--local  = V ''
local g_commit = P 'COMMIT' * P "\n"

local function taglist(tag)
  return function(...)
    local args = {...}
    if #args == 1 and type(args[1]) == "table" then
      args = args[1]
      args.tag = tag
    else
      args.tag = tag
    end
    return args
  end
end

local function ruletoken(tbl)
  return {tag = "token", value = tbl[1]:sub(tbl[2], tbl[3] - 1)}
end

local function ruletokenasgn(tbl, tag)
  tbl.token = tag
  return tbl
end


local ipt_grammar = {
  "start",
  start = g_table^1,
  g_table = Ct(
      g_header
    * g_name
    * Cg(Ct(g_dchain^0) / taglist("dchains"), "dchains")
    * Cg(Ct(g_uchain^0) / taglist("uchains"), "uchains")
    * Cg(Ct(g_rule^0) / taglist("rules") , "rules")
    * g_commit
    * g_footer
  ),

  g_header =
    P '# Generated' * (P(1) - P "\n")^1 *  P "\n",

  g_name =
    P "*" * Cg(g_iden, "name") *  P "\n",

  g_dchain = Ct(
    P ':' * Cg(g_iden, "name")
    * g_ws * Cg(g_iden, "policy")
    * g_ws * Cg(Ct(P '[' * Cg(g_port, "low") * P ':' * Cg(g_port, "high") * P ']'), "ports") * P "\n"
  ) / taglist("dchain"),

  g_port =
    g_number,

  g_uchain = Ct(
    P ':' * Cg(g_iden, "name") * g_ws * P '-' * g_ws
    * Cg(Ct(P '[' * Cg(g_port, "low") * P ':' * Cg(g_port, "high") * P ']'), "ports") * P "\n"
  ) / taglist("uchain"),

  g_rule =
    (g_rule_start * Ct(g_stats^0 * g_option * (g_ws * g_option)^1) * g_rule_end * g_rule_token)
      / ruletokenasgn
        * g_error * g_ws^0 * P "\n"^0,

  g_rule_start =
    Cg(Cp(), "rule_start"),

  g_rule_end =
    Cg(Cp(), "rule_end"),

  g_rule_token =
    Cg((Ct(Carg(1) * Cb("rule_start") * Cb("rule_end")) / ruletoken), "token"),

  g_error =
    (P(1) - P "\n")^0
      / function(str) if #str > 1 then error("this part of rule was not recognized: " .. str) end end,

  g_stats =
    Cg(Ct('[' * Cg(g_number, "packets") * P ':' * Cg(g_number, "bytes") * P ']' * g_ws ), "stats"),

  g_option = Ct(
      g_chain
    + g_source
    + g_destination
    + g_jump
    + g_protocol
    + g_in_interface
    + g_out_interface
    + g_match
    --[[+ Ct(
        (
            (P '-' * g_short_opt)
          + (P '--' * g_long_opt)
        )
          * Cg(Ct((g_ws * Ct(
            Cg(C(P '"' * (P(1) - P '"')^0 * P '"'), "string")
          + Cg(C(((P(1) - g_ws - P "\n")^1)), "value") - P '-'))^1), "values")
    )]]
  ),


  g_number =
    Cg( (
        P '0'
      + R'19' * g_digit^0
    ), "number"),
----------------------

  g_chain =
    (P '-A' + P '--append')
      * g_ws
        * Cg(g_iden, "chain"),

  g_source =
    Cg((P '-s' + P '--source')
      * g_ws
        * Ct(
              Cg(g_ip4_addr, "ip4")
                * (P '/' * Cg(g_ip4_mask, "ip4mask"))^0
            + g_iden
        ) / taglist("slashlist"), "source"),

  g_destination =
    Cg((P '-d' + P '--destination')
      * g_ws
        * Ct(
              Cg(g_ip4_addr, "ip4")
                * (P '/' * Cg(g_ip4_mask, "ip4mask"))^0
            + g_iden
        ) / taglist("slashlist"), "destination"),

  g_ip4_addr =
    g_ip4_addr_part * (P '.' * g_ip4_addr_part)^-3,

  g_ip4_addr_part = (
      P '2' * R '05' * R '09'
    + P '1' * R '09' * R '09'
    + R '19' * R '09'
    + R '09'
  ),

  g_ip4_mask =(
      P '3' * R '02'
    + R '12' * R '09'
    + R '09'
  ),

  g_jump =
    Cg((P '-j' + P '--jump')
      * g_ws * Ct(
          Cg(P 'REJECT', "target") * Cg(Ct((g_ws * g_reject_opt)^0), "options")
        + Cg(P 'NFLOG', "target") * Cg(Ct((g_ws * g_nflog_opt)^0), "options")
        + Cg(g_iden, "target")
      ), "jump"),

  g_nflog_opt = (
      P '--nflog-group' * g_ws * Cg(g_number, "nflog-group")
    + P '--nflog-prefix' * g_ws * Cg(g_string, "nflog-prefix")
    + P '--nflog-range' * g_ws * Cg(g_number, "nflog-range")
    + P '--nflog-threshold' * g_ws * Cg(g_number, "nflog-threshold")
  ),

  g_reject_opt =
    (P '--reject-with')
      * g_ws
        * Cg(
            P 'icmp-net-unreachable'
          + P 'icmp-host-unreachable'
          + P 'icmp-port-unreachable'
          + P 'icmp-proto-unreachable'
          + P 'icmp-net-prohibited'
          + P 'icmp-host-prohibited'
          + P 'icmp-admin-prohibited', "reject-with"),

  g_protocol =
    ((P '-p' + P '--protocol')
      * g_ws
        * Cg(
            P 'tcp'
          + P 'udp'
          + P 'udplite'
          + P 'icmp'
          + P 'esp'
          + P 'ah'
          + P 'sctp'
          + P 'all', "protocol")),

  g_in_interface =
    (P '-i' + P '--in-interface')
      * g_ws
        * Cg(g_iden, "in-interface"),

  g_out_interface =
    (P '-o' + P '--out-interface')
      * g_ws
        * Cg(g_iden, "out-interface"),


  g_match =
    (P '-m' + P '--match')
      * g_ws * Cg(Ct(
          P 'state' * Cg(Ct((g_ws * g_m_state)^1), "state")
        + P 'limit' * Cg(Ct((g_ws * g_m_limit)^1), "limit")
        + P 'tcp' * Cg(Ct((g_ws * g_m_tcp)^1), "tcp")
        + P 'udp' * Cg(Ct((g_ws * g_m_udp)^1), "udp")
        + P 'icmp' * Cg(Ct((g_ws * g_m_icmp)^1), "icmp")
        + P 'owner' * Cg(Ct((g_ws * g_m_owner)^1), "owner")
      ), "match"),


  g_m_state =
    (P '--state')
      * g_ws
        * Cg(Ct(C(g_m_state_opt) * (P ',' * C(g_m_state_opt))^0) / taglist("commalist"), "state"),

  g_m_state_opt = (
      P 'INVALID'
    + P 'ESTABLISHED'
    + P 'NEW'
    + P 'RELATED'
    + P 'UNTRACKED'
  ),

  g_m_limit = (
      (P '--limit') * g_ws * Cg(Ct(
        C(g_number) * P '/'
          * C(
              (P 'second' + P 'sec')
            + (P 'minute' + P 'min')
            + (P 'hour')
            + (P 'day')
          )
      ) / taglist("slashlist"), "limit")
    + (P '--limit-burst') * g_ws
        * g_number
  ),

  g_m_tcp = (
      g_sport
    + g_dport
    + g_tcp_flags
  ),

  g_m_udp = (
      g_sport
    + g_dport
  ),

   g_sport =
    (P '--sport' + P '--source-port')
      * g_ws
        * Cg(Ct(C(g_port) * (P ':' * C(g_port))^-1) / taglist("colonlist"), "sport"),

  g_dport =
    (P '--dport' + P '--destination-port')
      * g_ws
        * Cg(Ct(C(g_port) * (P ':' * C(g_port))^-1) / taglist("colonlist"), "dport"),

 g_tcp_flags =
    (P '--tcp-flags')
      * g_ws * Cg((
        Ct(Cg(Ct(C(g_tcp_flags_opt) * (P ',' * C(g_tcp_flags_opt))^0) / taglist("commalist"), "mask")
          * g_ws
            * Cg(Ct(C(g_tcp_flags_opt) * (P ',' * C(g_tcp_flags_opt))^0) / taglist("commalist"), "comp") )
      ), "tcp-flags"),

  g_tcp_flags_opt = (
      P 'SYN'
    + P 'ACK'
    + P 'FIN'
    + P 'RST'
    + P 'URG'
    + P 'PSH'
    + P 'ALL'
    + P 'NONE'
  ),

  g_m_icmp =
    (P '--icmp-type')
      * g_ws * Cg(Ct(
          C(P 'any')
        + C(P 'echo-reply' + P'0')
        + C((P 'pong' + P'0') + (P 'destination-unreachable' + P'3'))
            * ( P '/' * C(
               (P 'network-unreachable' + P'0')
             + (P 'host-unreachable' + P'1')
             + (P 'protocol-unreachable' + P'2')
             + (P 'port-unreachable' + P'3')
             + (P 'fragmentation-needed' + P'4')
             + (P 'source-route-failed' + P'5')
             + (P 'network-unknown' + P'6')
             + (P 'host-unknown' + P'7')
             + (P 'network-prohibited' + P'9')
             + (P 'host-prohibited' + P'10')
             + (P 'TOS-network-unreachable' + P'11')
             + (P 'TOS-host-unreachable' + P'12')
             + (P 'communication-prohibited' + P'13')
            ))^0
        + C(P 'host-precedence-violation')
        + C(P 'precedence-cutoff')
        + C(P 'source-quench' + P'4')
        + C(P 'redirect' + P'5')
            * ( P '/' * C(
               (P 'network-redirect' + P'0')
             + (P 'host-redirect' + P'1')
             + (P 'TOS-network-redirect' + P'2')
             + (P 'TOS-host-redirect' + P'3')
            ))^0
        + C(P 'echo-request' + P'8')
        + C(P 'ping' + P'8')
        + C(P 'router-advertisement' + P'9')
        + C(P 'router-solicitation' + P'10')
        + C((P 'time-exceeded' + P'11') + (P 'ttl-exceeded' + P'11'))
            * C( P '/' * (
               (P 'ttl-zero-during-transit' + P'0')
             + (P 'ttl-zero-during-reassembly' + P'1')
            ))^0
        + C(P 'parameter-problem' + P'12')
            * ( P '/' * C(
               (P 'ip-header-bad' + P'0')
             + (P 'required-option-missing' + P'1')
            ))^0
        + C(P 'timestamp-request' + P'13')
        + C(P 'timestamp-reply' + P'14')
        + C(P 'address-mask-request' + P'17')
        + C(P 'address-mask-reply' + P'18')
      ) / taglist("slashlist"), "icmp-type"),

  g_m_owner = (
      P '--uid-owner'
        * g_ws
          * Cg(g_iden, "uid-owner")
    + P '--gid-owner'
        * g_ws
          * Cg(g_iden, "gid-owner")
  ),

----------------------
  g_long_opt =
    Cg(g_iden, "long_opt"),
  g_short_opt =
    Cg((R 'AZ' + R 'az'), "short_opt"),
  g_footer =
    P '# Completed' * (P(1) - P "\n")^1 *  P "\n",
}

local function match(src)
  local ret, es = lpeg.match(Ct(ipt_grammar) * Cp(), src, nil, src)
  if es and (es - 1 < #src) then
    print(src:sub(es, #src))
    assert(es - 1 == #src)
  end
  assert(es, "could not parse iptable output")
  return ret
end

return match
