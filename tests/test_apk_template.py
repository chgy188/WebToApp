"""Guards for the embedded WebView Activity source in apk_builder.

The Java template ships as a string (ACTIVITY_JAVA) and is compiled on the
build host, far away from CI — so these tests assert the load-bearing pieces
of the source stay intact rather than executing anything.
"""

import json
import re
import shutil
import struct
import subprocess

import pytest

import server.engine.apk_builder as apk_builder
from server.engine.apk_builder import ACTIVITY_JAVA, MANIFEST_XML, ApkBuilder


def test_activity_java_braces_balanced():
    # Catches truncated / badly merged template edits before they reach the
    # build host and fail there with a cryptic javac error.
    assert ACTIVITY_JAVA.count("{") == ACTIVITY_JAVA.count("}")


def test_file_chooser_is_wired_end_to_end():
    # Issue #16: <input type="file"> did nothing because AppChromeClient never
    # overrode onShowFileChooser (WebView has no default picker).
    assert "@Override public boolean onShowFileChooser(" in ACTIVITY_JAVA
    assert "startActivityForResult(intent, REQ_FILE_CHOOSER)" in ACTIVITY_JAVA
    assert "protected void onActivityResult" in ACTIVITY_JAVA
    assert "if (requestCode != REQ_FILE_CHOOSER) return;" in ACTIVITY_JAVA
    assert "callback.onReceiveValue(parseFileChooserResult(resultCode, data))" in ACTIVITY_JAVA
    assert "private Uri[] parseFileChooserResult(int resultCode, Intent data)" in ACTIVITY_JAVA


def test_file_chooser_callback_always_settled():
    # A callback that is never answered makes WebView silently drop every
    # later <input type="file"> tap, so both the stale-chooser path and the
    # cancel path must deliver null.
    assert ACTIVITY_JAVA.count("pendingFileChoiceCallback.onReceiveValue(null)") == 1
    assert "callback.onReceiveValue(parseFileChooserResult(resultCode, data))" in ACTIVITY_JAVA


def test_file_chooser_imports_present():
    assert "import android.content.ClipData;" in ACTIVITY_JAVA
    assert "import android.webkit.ValueCallback;" in ACTIVITY_JAVA


def test_template_revision_is_bumped_slug():
    # The human-readable prefix keeps the date-slug convention...
    revision = ApkBuilder.TEMPLATE_REVISION
    parts = revision.split("-")
    assert len(parts) >= 4
    assert all(part.isdigit() for part in parts[:3])  # YYYY-MM-DD prefix
    assert parts[3]  # feature slug


def test_effective_revision_tracks_template_content(monkeypatch):
    # ...but the EFFECTIVE revision appends a content hash, so editing the
    # Java/manifest can never silently serve a stale cached template (the
    # old hand-bumped constant relied on developers remembering to bump it).
    effective = ApkBuilder._template_revision()
    assert effective.startswith(ApkBuilder.TEMPLATE_REVISION + "-")
    assert len(effective.rsplit("-", 1)[-1]) == 12
    monkeypatch.setattr("server.engine.apk_builder.ACTIVITY_JAVA", ACTIVITY_JAVA + "\n// touched")
    changed = ApkBuilder._template_revision()
    assert changed != effective
    assert changed.startswith(ApkBuilder.TEMPLATE_REVISION + "-")


def test_manifest_targets_current_sdk():
    # Issue #32: targetSdk 33 read as stale tool output and got APKs flagged.
    # Android requires targetSdk >= 34 for store updates; keep the generated
    # APK pinned to the current platform level (36).
    assert 'android:targetSdkVersion="36"' in MANIFEST_XML


def test_immersive_mode_handles_edge_to_edge_enforcement():
    # targetSdk 35+ enforces edge-to-edge and ignores the legacy
    # setSystemUiVisibility immersive flags, so API 35+ must go through
    # WindowInsetsController with inset padding on the WebView.
    assert "Build.VERSION_CODES.BAKLAVA" in ACTIVITY_JAVA
    assert "setOnApplyWindowInsetsListener" in ACTIVITY_JAVA
    assert "WindowInsets.CONSUMED" in ACTIVITY_JAVA


# ===== In-page file export bridge (issue #37) =====
#
# window.android.downloadFile does not exist in our APK, and DownloadManager
# cannot fetch blob:/data: URLs, so page-side exports failed silently. The
# template now exposes window.WebToApp.saveFile and resolves blob:/data:
# downloads natively. Like the file-chooser guards above, these assert the
# load-bearing source pieces stay intact (the template compiles far away).


def test_export_bridge_is_registered():
    assert 'webView.addJavascriptInterface(webBridge, "WebToApp")' in ACTIVITY_JAVA
    assert "import android.webkit.JavascriptInterface;" in ACTIVITY_JAVA
    assert "@JavascriptInterface public void saveFile(" in ACTIVITY_JAVA
    assert "@JavascriptInterface public void onExportFailed(" in ACTIVITY_JAVA


def test_export_bridge_writes_to_public_downloads():
    # Q+: MediaStore public collection (visible in file managers, no
    # permission needed). Pre-Q: public dir + media scan broadcast.
    assert "MediaStore.Downloads.EXTERNAL_CONTENT_URI" in ACTIVITY_JAVA
    assert "MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS" in ACTIVITY_JAVA
    assert "getExternalStoragePublicDirectory(" in ACTIVITY_JAVA
    assert "ACTION_MEDIA_SCANNER_SCAN_FILE" in ACTIVITY_JAVA
    assert "import android.provider.MediaStore;" in ACTIVITY_JAVA


def test_blob_and_data_downloads_resolved_natively():
    assert 'lower.startsWith("blob:")' in ACTIVITY_JAVA
    assert 'lower.startsWith("data:")' in ACTIVITY_JAVA
    assert "resolveBlobDownload(url, name, mime)" in ACTIVITY_JAVA
    assert "evaluateJavascript(script, null)" in ACTIVITY_JAVA
    # The fetch snippet must stay double-quote-free so neither the Java nor
    # the Python template layer needs escaping. Compare literal *contents*
    # (delimiters excluded) — the Java "..." delimiters themselves obviously
    # contain quotes.
    block = ACTIVITY_JAVA.split("BLOB_FETCH_PREFIX =", 1)[1].split(
        "private void resolveBlobDownload", 1)[0]
    js = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', block))
    assert '"' not in js
    assert "fetch(u)" in js and "WebToApp.saveFile" in js


def test_download_failures_are_visible():
    # Issue #37's core pain was silent failure: every catch swallowed the
    # error. Failures must now surface via logcat and an on-screen Toast.
    assert "enqueueDownload failed" in ACTIVITY_JAVA
    assert "Toast.makeText(M.this, message, Toast.LENGTH_LONG).show()" in ACTIVITY_JAVA
    assert "import android.widget.Toast;" in ACTIVITY_JAVA
    assert "import android.util.Log;" in ACTIVITY_JAVA


def test_notification_permission_nudged_not_blocking():
    assert '<uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>' in MANIFEST_XML
    assert "REQ_NOTIFY" in ACTIVITY_JAVA
    assert '"android.permission.POST_NOTIFICATIONS"' in ACTIVITY_JAVA


# ===== Forkless per-app patching (issue #34) =====
#
# The per-app APK path must not run apktool; it rewrites ZIP entries of the
# cached template directly. The AXML patcher is exercised against a fixture
# manifest compiled by aapt2 (not the build host) so CI never needs an SDK.

def _u16pool(s: str) -> bytes:
    # One pool entry: u16 length prefix + UTF-16 data + NUL terminator.
    return struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"


_AXML_FIXTURE = (
    b"\x03\x00\x0c\x00\x8c\x0b\x00\x00"  # RES_XML doc header: type 3, size 3004
    b"\x01\x00\x1c\x00\x84\x04\x00\x00"  # string pool: type 1, header 28
    + struct.pack("<IIIII", 6, 0, 0, 52, 0)  # stringsStart: 28 header + 6*4 offsets
    + struct.pack("<6I", 0, 46, 84, 110, 136, 146)
    + _u16pool("com.webtoapp.template")
    + _u16pool("WebToApp Template")
    + _u16pool("versionCode")
    + _u16pool("versionName")
    + _u16pool("1.0")
    + _u16pool("2.0")
    + b"\x00" * 2  # pool padding to 4-byte boundary
    # START_ELEMENT for <manifest>: type 0x0102, header 16, size 96;
    # attrExt: ns, name, attrStart=20, attrSize=20, attrCount=4, next=0, ...
    + b"\x02\x01\x10\x00\x60\x00\x00\x00"
    + b"\x00\x00\x00\x00\x00\x00\x00\x00"  # line number + comment
    + b"\xff\xff\xff\xff"  # ns = -1
    + b"\x01\x00\x00\x00"  # element name index
    + b"\x14\x00\x14\x00\x04\x00\x00\x00\x00\x00\x00\x00"  # attrExt tail
    # attribute records: ns, name_idx, raw_idx, typed_value, value
    + b"\xff\xff\xff\xff" + struct.pack("<I", 2) + b"\xff\xff\xff\xff"
    + struct.pack("<II", 0x10000008, 1)  # versionCode = 1 (INT_DEC)
    + b"\xff\xff\xff\xff" + struct.pack("<I", 3) + struct.pack("<I", 4)
    + struct.pack("<II", 0x03000008, 4)  # versionName = "1.0" (STRING)
    + b"\xff\xff\xff\xff" + struct.pack("<I", 0) + b"\xff\xff\xff\xff"
    + struct.pack("<II", 0x03000008, 0)  # package = "com.webtoapp.template"
    + b"\xff\xff\xff\xff" + struct.pack("<I", 1) + b"\xff\xff\xff\xff"
    + struct.pack("<II", 0x03000008, 1)  # label = "WebToApp Template"
)


def test_axml_patcher_swaps_pool_strings_and_version_code():
    from server.engine.apk_builder import _AxmlPatcher

    patched = _AxmlPatcher(_AXML_FIXTURE).patch(
        {"com.webtoapp.template": "com.webtoapp.ae877d6c2", "WebToApp Template": "Sdk36Verify"},
        version_code=42,
    )
    strings = _AxmlPatcher(patched)._string_pool(patched)
    assert strings[0] == "com.webtoapp.ae877d6c2"
    assert strings[1] == "Sdk36Verify"
    # untouched entries keep their pool slots
    assert strings[4] == "1.0" and strings[5] == "2.0"


def test_axml_patcher_rejects_utf8_pool():
    from server.engine.apk_builder import _AxmlPatcher

    utf8_flagged = bytearray(_AXML_FIXTURE)
    # Pool header: type(2) headerSize(2) size(4) count(4) styleCount(4) flags(4)
    # → the flags field sits at absolute offset 8+16=24; aapt2 marks UTF-8
    # pools with 1<<8 in that 32-bit little-endian field.
    struct.pack_into("<I", utf8_flagged, 24, struct.unpack_from("<I", utf8_flagged, 24)[0] | 0x100)
    with pytest.raises(ValueError):
        _AxmlPatcher(bytes(utf8_flagged)).patch({"com.webtoapp.template": "com.webtoapp.ae877d6c2"}, version_code=2)


# ===== TV profile (P0) =====
#
# The TV work lives in the shared template, so an API 21 device must be able
# to load its config, and a TV launcher must actually see the app. These are
# source-level guards because CI has no Android SDK to compile with.


def test_config_loading_is_api21_safe():
    assert "input.readAllBytes()" not in ACTIVITY_JAVA
    assert "import java.io.ByteArrayOutputStream;" in ACTIVITY_JAVA
    assert "ByteArrayOutputStream buffer = new ByteArrayOutputStream();" in ACTIVITY_JAVA
    assert "while ((count = input.read(chunk)) != -1)" in ACTIVITY_JAVA


def test_manifest_supports_tv_launchers():
    assert "android.intent.category.LEANBACK_LAUNCHER" in MANIFEST_XML
    assert 'android:name="android.software.leanback" android:required="false"' in MANIFEST_XML
    assert 'android:name="android.hardware.touchscreen" android:required="false"' in MANIFEST_XML
    assert 'android:configChanges="orientation|screenSize' in MANIFEST_XML


def test_html5_video_fullscreen_is_wired():
    assert "@Override public void onShowCustomView(View view, CustomViewCallback callback)" in ACTIVITY_JAVA
    assert "@Override public void onHideCustomView()" in ACTIVITY_JAVA
    assert "setContentView(fullscreenContainer)" in ACTIVITY_JAVA
    assert "setContentView(webView)" in ACTIVITY_JAVA
    assert "webView.getWebChromeClient().onHideCustomView()" in ACTIVITY_JAVA


def test_tv_fullscreen_uses_a_trusted_click_button():
    block = ACTIVITY_JAVA.split(
        "private static final String TV_FULLSCREEN_JS =", 1)[1].split(
        "private WebView webView;", 1)[0]
    js = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', block))
    assert '"' not in js
    assert "requestFullscreen" in js and "webkitRequestFullscreen" in js
    assert "querySelectorAll('video')" in js
    assert "__wtaTvFsBtn" in js
    assert "onPageFinished(WebView view, String url)" in ACTIVITY_JAVA
    assert "view.evaluateJavascript(TV_FULLSCREEN_JS, null)" in ACTIVITY_JAVA
    # Fullscreen API needs user activation; OK is routed through a trusted
    # touch on the injected button instead of evaluateJavascript().click().
    assert "MotionEvent.ACTION_DOWN" in ACTIVITY_JAVA
    assert "setFullscreenButtonRect" in ACTIVITY_JAVA
    # SPAs render <video> after onPageFinished, so the button focuses itself
    # via a short polling timer rather than a one-shot check at injection.
    assert "var fsTimer=setInterval(function()" in js
    assert "querySelector('video')" in js
    # The four TV buttons must exist only on pages that actually have video.
    assert "btn.style.display='none'" in js
    assert "btn.style.display=v?'block':'none'" in js


def test_tv_cc_button_hidden_when_native_subtitles_exist():
    block = ACTIVITY_JAVA.split(
        "private static final String TV_SUBTITLES_JS =", 1)[1].split(
        "// Core ad/tracker network blocklist", 1)[0]
    js = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', block))
    assert "btn.style.display='none'" in js
    assert "v.textTracks&&v.textTracks.length" in js
    assert "btn.style.display=(v&&!nativeSubs)?'block':'none'" in js


def test_tv_focus_reaches_clickable_divs():
    block = ACTIVITY_JAVA.split(
        "private static final String TV_REMOTE_JS =", 1)[1].split(
        "// TV subtitles:", 1)[0]
    js = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', block))
    # Site floating buttons (home/theme) are plain divs with cursor:pointer.
    assert "div,span,li'" in js
    assert "st.cursor==='pointer'" in js
    assert "el.setAttribute('tabindex','-1')" in js
    # Every page starts at the top-left element; SPA navigation resets it too.
    assert "var topLeft=function()" in js
    assert "var resetFocus=function()" in js
    assert "setInterval(checkHref,400)" in js
    # Strict directional movement: only elements in the pressed direction,
    # preferring same-row / same-column aligned targets.
    assert "if(main<=8)continue;" in js
    assert "var pool=aligned.length?aligned:loose;" in js


def test_tv_back_never_finishes_app_on_subpages():
    assert "private boolean isHomePage(String url)" in ACTIVITY_JAVA
    assert "private void performBrowserBack(String currentUrl)" in ACTIVITY_JAVA
    assert "if (!isHomePage(currentUrl))" in ACTIVITY_JAVA
    assert "if (webView.canGoBack()) webView.goBack();" in ACTIVITY_JAVA
    assert "else if (config != null && config.url != null) webView.loadUrl(config.url);" in ACTIVITY_JAVA
    # BACK is consumed by dispatchKeyEvent in TV mode (both DOWN and UP).
    assert "event.getKeyCode() == KeyEvent.KEYCODE_BACK" in ACTIVITY_JAVA
    assert "__wtaTvBack==='function'&&__wtaTvBack()" in ACTIVITY_JAVA
    assert "performBrowserBack(webView != null ? webView.getUrl() : null);" in ACTIVITY_JAVA
    assert "view.evaluateJavascript(TV_BACK_JS, null)" in ACTIVITY_JAVA


def test_tv_back_closes_modals_before_navigating():
    block = ACTIVITY_JAVA.split(
        "private static final String TV_BACK_JS =", 1)[1].split(
        "// Core ad/tracker network blocklist", 1)[0]
    js = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', block))
    assert "window.__wtaTvBack=function()" in js
    assert "var findModal=function()" in js
    assert "var findClose=function(dlg)" in js
    assert "new KeyboardEvent('keydown'" in js
    assert "window.WebToApp.performBack(location.href)" in js
    assert "var closeLike=function(e)" in js
    assert "var log=function(m)" in js
    assert "performBack(final String currentUrl)" in ACTIVITY_JAVA
    assert "logBack(String info)" in ACTIVITY_JAVA


def test_tv_back_escalates_until_modal_gives_up():
    # A site login popup whose × is not a plain click target used to eat BACK
    # forever: every press re-tried the same close button and never reached
    # browser-back, so the user could neither close it, go back, nor quit.
    block = ACTIVITY_JAVA.split(
        "private static final String TV_BACK_JS =", 1)[1].split(
        "// Core ad/tracker network blocklist", 1)[0]
    js = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', block))
    assert '"' not in js
    assert "var state={sig:'',tries:0}" in js
    for step in ("state.tries===1", "state.tries===2", "state.tries===3",
                 "modal-giveup", "modal-corner", "modal-history"):
        assert step in js
    # Escalation: close button -> corner/backdrop touch -> history.back() ->
    # native browser back (which finishes the app on the home page).
    assert "var backdropOf=function(dlg)" in js
    assert "var closeAtCorner=function(dlg)" in js
    assert "var touch=function(el)" in js
    assert "window.history.back()" in js
    assert "window.WebToApp.performBack(location.href)" in js


def test_tv_back_held_exits_app_as_last_resort():
    # The TV guard consumes BACK unconditionally, so a modal that survives all
    # escalation steps would leave no way out. A held BACK must always quit.
    assert "private void exitApp()" in ACTIVITY_JAVA
    assert "finishAffinity();" in ACTIVITY_JAVA
    assert "event.getRepeatCount() >= 12" in ACTIVITY_JAVA


def test_tv_input_keypad_covers_phone_and_code_fields():
    # A TV remote cannot drive the system IME, so the site's phone / code
    # fields were focusable but untypeable. Focusing one must open an injected
    # DPAD-operable numeric keypad.
    block = ACTIVITY_JAVA.split(
        "private static final String TV_INPUT_JS =", 1)[1].split(
        "// Core ad/tracker network blocklist", 1)[0]
    js = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', block))
    assert '"' not in js
    assert "window.__wtaTvOpenPad=function(el)" in js
    assert "window.__wtaTvClosePad=function()" in js
    assert "window.__wtaTvPadCandidates=function()" in js
    assert "Object.getOwnPropertyDescriptor(el.constructor.prototype,'value')" in js
    assert "dispatchEvent(new Event('input',{bubbles:true}))" in js
    for label in ("'删除'", "'清空'", "'完成'"):
        assert label in js
    assert "view.evaluateJavascript(TV_INPUT_JS, null)" in ACTIVITY_JAVA
    remote = ACTIVITY_JAVA.split(
        "private static final String TV_REMOTE_JS =", 1)[1].split(
        "// TV subtitles:", 1)[0]
    rjs = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', remote))
    assert "if(window.__wtaTvOpenPad&&window.__wtaTvOpenPad(el))return;" in rjs
    assert "if(window.__wtaTvPadEl&&window.__wtaTvPadCandidates)" in rjs
    # While a popup is open, DPAD must stay inside it instead of wandering
    # over the page behind the mask.
    assert "typeof window.__wtaTvFindModal==='function'" in rjs
    back = ACTIVITY_JAVA.split(
        "private static final String TV_BACK_JS =", 1)[1].split(
        "// Core ad/tracker network blocklist", 1)[0]
    bjs = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', back))
    assert "window.__wtaTvClosePad&&window.__wtaTvClosePad()" in bjs
    # A full-screen overlay (login route) must leave on the first BACK, not
    # spend three presses re-trying close buttons that do not exist.
    assert "window.innerWidth*0.7" in bjs


def test_tv_home_back_asks_before_exiting():
    # A stray BACK on the landing page used to quit instantly; on a TV remote
    # that is easy to hit by accident. It now asks first.
    assert "private void showExitConfirm()" in ACTIVITY_JAVA
    assert 'setText("退出应用")' in ACTIVITY_JAVA
    assert 'setText("确定要退出吗？")' in ACTIVITY_JAVA
    assert 'quit.setText("退出")' in ACTIVITY_JAVA
    assert 'cancel.setText("取消")' in ACTIVITY_JAVA
    assert "showExitConfirm();" in ACTIVITY_JAVA
    # The confirmation must be an in-window overlay, not an AlertDialog: a dialog
    # gets its own window whose DPAD keys the Activity branches swallowed, so
    # the buttons were unreachable by remote.
    assert "AlertDialog" not in ACTIVITY_JAVA
    assert "private FrameLayout exitOverlay;" in ACTIVITY_JAVA
    assert "private void hideExitConfirm()" in ACTIVITY_JAVA
    assert "if (exitOverlay != null)" in ACTIVITY_JAVA
    # While the overlay is up, BACK cancels and everything else reaches the
    # focused button through normal view dispatch.
    assert "hideExitConfirm();\n                return true;" in ACTIVITY_JAVA
    assert "return super.dispatchKeyEvent(event);" in ACTIVITY_JAVA
    # The page-side full-screen overlay path must defer to native, which is
    # what decides "close the page" vs "ask to exit".
    js = "".join(re.findall(
        r'"((?:[^"\\]|\\.)*)"',
        ACTIVITY_JAVA.split("private static final String TV_BACK_JS =", 1)[1].split(
            "// Core ad/tracker network blocklist", 1)[0]))
    assert "modal-page" in js
    page_branch = js.split("if(fr.width>=window.innerWidth*0.7", 1)[1].split("return;", 1)[0]
    assert "window.WebToApp.performBack(location.href)" in page_branch
    assert "window.history.back()" not in page_branch


def test_tv_native_fullscreen_routes_keys_and_has_exit_control():
    assert "private android.widget.Button fullscreenExitButton;" in ACTIVITY_JAVA
    assert "fullscreenExitButton.setOnClickListener" in ACTIVITY_JAVA
    assert "fullscreenExitButton.bringToFront()" in ACTIVITY_JAVA
    assert "if (customView != null) {" in ACTIVITY_JAVA
    assert "return handleFullscreenKey(event);" in ACTIVITY_JAVA
    assert "private boolean handleFullscreenKey(KeyEvent event)" in ACTIVITY_JAVA
    assert "private boolean dispatchFullscreenKey(KeyEvent event)" in ACTIVITY_JAVA
    assert "private void runFullscreenJsMedia(String action)" in ACTIVITY_JAVA
    assert "__wtaTvMedia==='function'&&__wtaTvMedia('" in ACTIVITY_JAVA
    assert "KEYCODE_MEDIA_REWIND" in ACTIVITY_JAVA


def test_tv_ok_activates_focused_element_not_always_fullscreen():
    # OK on a movie card must click THAT card; only the injected fullscreen
    # button gets the synthetic trusted touch required by requestFullscreen().
    assert "boolean focusIsFsBtn = true;" in ACTIVITY_JAVA
    assert "setFocusIsFsBtn(boolean value)" in ACTIVITY_JAVA
    assert "webBridge.focusIsFsBtn" in ACTIVITY_JAVA
    assert "__wtaTvActivate==='function'&&__wtaTvActivate()" in ACTIVITY_JAVA
    remote = ACTIVITY_JAVA.split(
        "private static final String TV_REMOTE_JS =", 1)[1].split(
        "// TV subtitles:", 1)[0]
    js = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', remote))
    assert "setFocusIsFsBtn" in js
    assert "focusin" in js
    assert "window.__wtaTvActivate=function()" in js
    assert "el.click();" in js


def test_tv_navigation_guard_is_enforced():
    assert "return tvMode && !isAllowedNavigationHost(trimmed);" in ACTIVITY_JAVA
    assert "private boolean isAllowedNavigationHost(String url)" in ACTIVITY_JAVA
    assert "isSameHostOrSubdomain(host, config.startHost)" in ACTIVITY_JAVA
    assert "if (tvMode) return true;" in ACTIVITY_JAVA
    # Server redirects never reach shouldOverrideUrlLoading.
    assert "!isAllowedNavigationHost(url)" in ACTIVITY_JAVA


def test_tv_navigation_allows_mobile_bare_host_variant():
    # Sites that redirect mobile WebView UAs between www./m./bare hosts must
    # not be bounced back to the start URL forever by the TV guard.
    assert "if (loaded.tvMode && loaded.startHost != null)" in ACTIVITY_JAVA
    assert 'bare.startsWith("www.")' in ACTIVITY_JAVA
    assert 'bare.startsWith("m.")' in ACTIVITY_JAVA
    assert "loaded.tvNavHosts.add(bare)" in ACTIVITY_JAVA


def test_tv_options_reach_apk_config():
    builder = ApkBuilder()
    cfg = json.loads(builder._config_json("https://example.com", {
        "feature-tv-mode": True,
        "feature-tv-auto-fullscreen": True,
        "feature-tv-remote": True,
        "feature-tv-subtitles": True,
        "feature-tv-extra-hosts": ["cdn.example.net"],
    }))
    assert cfg["tv_mode"] is True
    assert cfg["tv_auto_fullscreen"] is True
    assert cfg["tv_remote"] is True
    assert cfg["tv_subtitles"] is True
    assert cfg["tv_nav_hosts"] == ["cdn.example.net"]
    default = json.loads(builder._config_json("https://example.com", {}))
    assert default["tv_mode"] is False
    assert default["tv_auto_fullscreen"] is False
    assert default["tv_remote"] is False
    assert default["tv_subtitles"] is False
    assert default["tv_nav_hosts"] == []


def test_tv_remote_keys_are_consumed_by_activity():
    assert "import android.view.KeyEvent;" in ACTIVITY_JAVA
    assert "public boolean dispatchKeyEvent(KeyEvent event)" in ACTIVITY_JAVA
    assert "private static boolean isDpadKey(int keyCode)" in ACTIVITY_JAVA
    assert "private static String tvMediaAction(int keyCode)" in ACTIVITY_JAVA
    assert "webView.setFocusableInTouchMode(true);" in ACTIVITY_JAVA
    assert "webView.requestFocus();" in ACTIVITY_JAVA
    for action in ("toggle", "play", "pause", "ff", "rw", "next", "prev", "stop"):
        assert f'return "{action}";' in ACTIVITY_JAVA
    assert "config.tvMode && config.tvRemote" in ACTIVITY_JAVA
    assert "view.evaluateJavascript(TV_REMOTE_JS, null)" in ACTIVITY_JAVA


def test_tv_remote_js_stays_quote_simple():
    block = ACTIVITY_JAVA.split(
        "private static final String TV_REMOTE_JS =", 1)[1].split(
        "private static final Set<String> AD_HOSTS", 1)[0]
    js = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', block))
    assert '"' not in js
    for helper in ("__wtaTvMoveFocus", "__wtaTvActivate", "__wtaTvMedia"):
        assert helper in js
    assert "outline-offset:2px" in js
    assert "currentTime=Math.min(dur,v.currentTime+10)" in js
    assert "currentTime=Math.max(0,v.currentTime-10)" in js


def test_tv_subtitles_use_native_tracks_and_captions_key():
    block = ACTIVITY_JAVA.split(
        "private static final String TV_SUBTITLES_JS =", 1)[1].split(
        "private static final Set<String> AD_HOSTS", 1)[0]
    js = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', block))
    assert '"' not in js
    for marker in ("textTracks", "subtitleTracks", "subtitleTrack=-1",
                   "__wtaTvSubtitles", "关闭字幕"):
        assert marker in js
    assert "view.evaluateJavascript(TV_SUBTITLES_JS, null)" in ACTIVITY_JAVA
    assert "config.tvMode && config.tvSubtitles" in ACTIVITY_JAVA
    assert "KeyEvent.KEYCODE_CAPTIONS" in ACTIVITY_JAVA
    assert 'loaded.tvSubtitles = json.optBoolean("tv_subtitles", false);' in ACTIVITY_JAVA


def test_template_uses_only_real_keyevent_constants():
    # javac caught KEYCODE_MEDIA_TOGGLE, which is not an Android constant.
    assert "KEYCODE_MEDIA_TOGGLE" not in ACTIVITY_JAVA
    # The captions branch is outside the remote-key block, so it must read
    # the key code from the event itself.
    assert "event.getKeyCode() == KeyEvent.KEYCODE_CAPTIONS" in ACTIVITY_JAVA


@pytest.mark.skipif(shutil.which("javac") is None, reason="javac not installed")
def test_activity_java_compiles_when_toolchain_available(tmp_path):
    builder = ApkBuilder()
    jar = builder._find_jar()
    if not jar:
        pytest.skip("android.jar not available")
    src = tmp_path / "M.java"
    src.write_text(ACTIVITY_JAVA, encoding="utf-8")
    classes = tmp_path / "classes"
    classes.mkdir()
    proc = subprocess.run(
        [shutil.which("javac"), "-proc:none", "-encoding", "UTF-8",
         "-source", "1.8", "-target", "1.8", "-bootclasspath", jar,
         "-d", str(classes), str(src)],
        capture_output=True, text=True, errors="replace",
    )
    assert proc.returncode == 0, (proc.stdout + proc.stderr)[:4000]


def test_find_tools_handles_windows_suffixes(tmp_path, monkeypatch):
    bt = tmp_path / "build-tools" / "35.0.0"
    bt.mkdir(parents=True)
    (bt / "aapt2.exe").write_bytes(b"")
    builder = ApkBuilder()
    monkeypatch.setattr(builder, "sdk", str(tmp_path))
    monkeypatch.setattr(apk_builder.os, "name", "nt")
    assert str(bt / "aapt2.exe") in builder._find_tools("aapt2")
