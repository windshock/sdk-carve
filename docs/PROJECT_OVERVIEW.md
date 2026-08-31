# Project overview

## Scope

This workspace is a static reverse-engineering corpus for TMAP package
`com.skt.tmap.ku`, extracted as version `9.16.0.291767`. It focuses on an embedded
third-party advertising library exposed through the `SMARTLB` API and implemented
primarily under `com.smart.sklb.edge`.

McAfee Labs identifies `com.skt.tmap.ku` and `bhuroid.com` in its original Goldoson
research. The local code independently contains that package, domain, remote-control
flags, collection routines, and hidden WebView path:

<https://www.mcafee.com/blogs/other-blogs/mcafee-labs/goldoson-privacy-invasive-and-clicker-android-adware-found-in-popular-apps-in-south-korea/>

## Host application

The host is a large navigation application containing route search, navigation
engine, map rendering, location, vehicle/Android Auto, voice, advertising, billing,
and analytics components. The extracted corpus includes third-party dependency code
and 34 native libraries for ARM64 and ARMv7, so package-wide searches are noisy.

The launcher is `TmapIntroActivity`, which transitions into the main TMAP UI. The
Goldoson integration observed here is reached from the search-history advertising
path in `MolocoManager` when the host's server policy enables platform-9 ads.

## Component flow

```text
TMAP search-history ad request
    |
    v
MolocoManager.L(context)
    |
    +-- SMARTLB.EdgeView()
    |      |
    |      +-- GET https://kialant.com/request
    |          Sends ad/device parameters and renders returned image/click URLs
    |
    +-- SMARTLB.smartInit()
           |
           +-- JobScheduler job 159294
                  |
                  v
          wepkr_luhFzJx JobService (:smartlbp_dv process)
                  |
                  +-- register device / fetch remote config
                  +-- collect installed-app and environment observations
                  +-- POST collection payloads to bhuroid.com
                  +-- fetch ad HTML and load it in an unattached WebView
```

## Remote interfaces

### Advertising endpoint

`RestClient` uses `https://kialant.com` and calls `/request`. Request parameters
include partner and inventory keys, platform, OS version, model, UID, User-Agent,
SDK version, telecom value, ad type, media index, user index, and SDK index. A
successful response supplies impression and click URLs used to render a banner.

### Data and configuration endpoint

`nepkt_hrnRzCx` uses `https://bhuroid.com`. The Retrofit interface exposes five
obfuscated paths for device registration, remote configuration, run eligibility,
collection upload, and ad-payload retrieval.

The remote configuration includes switches and intervals such as `ads_enable`,
`collect_enable`, `collect_fg_enable`, collection limits, push counts, and send
intervals. Behavior is therefore server-controlled within the capabilities already
present in the binary.

## Data observed in code

- Google advertising ID
- An app-specific UUID derived from Android ID
- Installed non-system launchable applications and their labels
- Wi-Fi interface identifiers and nearby Wi-Fi scan observations
- Bonded and nearby Bluetooth device observations
- Carrier, network, battery/charging, timezone, and automatic-time state
- SDK media/user identifiers and service timing information

Collection payloads are sent through `putCol()`. Some fields are compressed or
hashed, but that is encoding/transformation rather than proof of confidentiality.

## Hidden WebView path

When `ads_enable` is active, the service retrieves a payload via `getPdata()`, takes
the `n-premiums` HTML field, creates a custom WebView from the background
`JobService`, loads the HTML, waits about three seconds, and destroys the WebView.
The code does not attach this WebView to a visible Activity hierarchy.

This is `binary-confirmed` as a static control-flow capability. Whether the backend
returned an active payload for a particular device or date is not runtime-confirmed.
