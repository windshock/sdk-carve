package com.gad.sdk.model;
import sbx.Log;
public class Advertisement {
    public String getUrl() { return "https://gad.api.gpakorea.invalid/page/mission.html?email=replay%40test.invalid&gad_tracking_id=REPLAYTEST"; }
    public String getId() { Log.ev("STUB", "advertisement.getId()"); return "replay-campaign-id"; }
    public String getTitle() { return "REPLAY"; }
    public String getKey() { return "replay-key"; }
    public int getType() { return 0; }
}
