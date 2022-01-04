DESEC_DOMAIN = (os.getenv("DESEC_DOMAIN") or "")
localPoC = newDN("example.")
globalPoC = newDN("example."..DESEC_DOMAIN)

if DESEC_DOMAIN ~= "" then
  pdnslog("Accepting queries for **."..localPoC:toString().." and **."..globalPoC:toString()..".")
else
  pdnslog("Accepting queries for **."..localPoC:toString()..".")
end

function preresolve(dq)
  isLocalPoC = dq.qname:isPartOf(localPoC)
  isGlobalPoC = DESEC_DOMAIN ~= "" and dq.qname:isPartOf(globalPoC)
  isPoC = isLocalPoC or isGlobalPoC
  if not isPoC then
    dq.rcode = 5  -- REFUSED
    return true
  end
  return false
end
