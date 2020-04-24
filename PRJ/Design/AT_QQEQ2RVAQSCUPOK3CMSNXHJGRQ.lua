while true do
    if Core['@FAILOVER_PRESENCE']==true and Core['@FAILOVER_ERROR']==false then
        Core.setReserve(nil, Core['@FAILOVER_RESERVED']);
    end
    os.sleep(0.05);
end
