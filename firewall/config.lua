
config = {
  family = 4;
  iptables_save = "/sbin/iptables-save";
  iptables = "/sbin/iptables";
  targets = {
    ["NFLOG"]   = target { name = "NFLOG", color="orange" };
    ["REJECT"]  = target { name = "REJECT", color="red" };
    ["ACCEPT"]  = target { name = "ACCEPT", color="darkgreen" };
    ["LOG"]     = target { name = "LOG", color="orange" };
    ["DROP"]    = target { name = "DROP", color="magenta" };
    ["RETURN"]  = target { name = "RETURN", color="yellow" };
  };
}
