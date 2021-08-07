// Clara test example
  
rw :: IPRewriter(pass 0);

rw[0] -> Discard;

FromDevice(ens6f0)
        //-> Strip(14)
        //-> CheckIPHeader(BADSRC 18.26.4.255 2.255.255.255 1.255.255.255)
        //-> ClaraForceTCP()
        //-> ClaraAnonIPAddr()
        //-> ClaraUDPIPEncap()
        //-> ClaraTimeFilter()
        //-> ClaraTCPACK()
        //-> ClaraTCPResp()
        //-> ClaraTCPGen()
        //-> ClaraAggCounter() 
        //-> ClaraIPReWriter()
        -> Print(ok)
        -> [0]rw;
