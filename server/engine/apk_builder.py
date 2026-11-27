"""
Android APK Builder.

Primary strategy:
1. Reuse a cached template WebView APK.
2. Patch package name / app name / version / icon / assets URL by rewriting
   the affected ZIP entries in place (AXML string-pool edit for the
   manifest) — no apktool round-trip in the per-app path.
3. Re-align and sign with a per-app keystore (one signing certificate per
   app_id; generated on first build and reused on every later build of the
   same app_id so reinstalls are accepted as updates).

Fallback strategy:
1. Build the minimal WebView shell from source if SDK tools are available.
2. Cache the result as the template APK.
3. If all else fails, emit the legacy ZIP fallback package.
"""

import hashlib
import html
import json
import os
import re
import secrets
import shutil
import struct
import subprocess
import tempfile
import threading
import zipfile
import zlib
from collections import OrderedDict
from pathlib import Path
from urllib.parse import urlparse

from server import config
from server.engine import apk_v2_signer
from server.logging_util import log_event


def _run_tool(cmd, **kwargs):
    """subprocess.run with a wall-clock cap (#242): a hung aapt2/d8/javac/
    openssl must not pin a build worker forever. Timeout propagates as
    subprocess.TimeoutExpired and the build fails cleanly (PWA fallback)."""
    kwargs.setdefault("timeout", config.tool_timeout_seconds())
    return subprocess.run(cmd, **kwargs)


class _AxmlPatcher:
    """Minimal binary (compiled) Android XML editor.

    The template manifest is compiled by our own aapt2 build, so patching per
    app is a bounded edit of two AXML structures instead of an apktool
    decode/re-encode round-trip:

    1. The global UTF-16 string pool: strings are replaced **by content** and
       the pool is re-serialized with the same entry order and count. Element
       chunks reference strings by *index*, not offset, so as long as the
       order is unchanged every other chunk stays valid — only the byte
       offsets after the pool shift, and those are carried by chunk headers
       which we rewrite.
    2. ``android:versionCode`` attribute: the manifest element carries the
       value as a raw little-endian int32 in its attribute payload; rewrite
       it in place (offsets re-derived from the rebuilt stream).
    """

    _RES_XML_TYPE = 0x0003  # RES_XML doc header
    _STRING_POOL_TYPE = 0x0001
    _START_ELEMENT_TYPE = 0x0102
    _UTF8_FLAG = 1 << 8

    def __init__(self, axml: bytes):
        self._axml = axml

    def patch(self, string_swaps: dict, version_code: int) -> bytes:
        strings = self._string_pool(self._axml)
        rebuilt = [
            string_swaps.get(s, s) for s in strings
        ]
        if rebuilt == strings and version_code == 1:
            return self._axml
        data = self._rebuild_pool(self._axml, rebuilt)
        return self._patch_version_code(data, version_code)

    def _rebuild_pool(self, data: bytes, strings: list) -> bytes:
        """Re-serialize the string pool with new contents, same order/count.

        Everything after the pool shifts by the size delta; the pool chunk
        header and the wrapping RES_XML doc header are rewritten accordingly.
        Subsequent chunk contents never carry absolute offsets to the pool
        (references are indices), so a plain shift is safe.
        """
        pos = self._first_chunk_end(data)
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, pos)
        if chunk_type != self._STRING_POOL_TYPE:
            raise ValueError("AXML: string pool chunk not found")
        string_count, style_count, flags, strings_start, styles_start = struct.unpack_from(
            "<IIIII", data, pos + 8
        )
        if flags & self._UTF8_FLAG:
            raise ValueError("AXML: UTF-8 string pools not supported")
        if style_count or styles_start:
            raise ValueError("AXML: styled strings not supported")

        header = bytearray(data[pos:pos + header_size])
        body = bytearray()
        offsets = []
        for s in strings:
            encoded = s.encode("utf-16-le")
            offsets.append(len(body))
            u16len = len(s)
            if u16len >= 0x8000:
                body += struct.pack("<HH", (u16len >> 16) | 0x8000, u16len & 0xFFFF)
            else:
                body += struct.pack("<H", u16len)
            body += encoded
            body += b"\x00\x00"  # NUL terminator
        # 4-byte align the strings block
        while len(body) % 4:
            body += b"\x00"

        strings_start_new = header_size + string_count * 4
        struct.pack_into("<I", header, 20, strings_start_new)  # stringsStart @ +20
        new_pool = bytes(header) + struct.pack(f"<{string_count}I", *offsets) + bytes(body)

        out = bytearray(data[:pos] + new_pool + data[pos + chunk_size:])
        # Fix sizes: pool chunk header (offset 4) and the outer doc header (offset 4).
        struct.pack_into("<I", out, pos + 4, len(new_pool))
        doc_type, _hs, doc_size = struct.unpack_from("<HHI", out, 0)
        if doc_type == self._RES_XML_TYPE:
            struct.pack_into("<I", out, 4, doc_size + (len(new_pool) - chunk_size))
        return bytes(out)

    def _patch_version_code(self, data: bytes, version_code: int) -> bytes:
        """Rewrite the manifest element's android:versionCode int attribute.

        Walks the AXML chunk stream to find the first START_ELEMENT (the
        ``<manifest>`` element) and patches the attribute whose name resolves
        to ``versionCode`` in the string pool.
        """
        data = bytearray(data)
        strings = self._string_pool(data)
        idx = strings.index("versionCode") if "versionCode" in strings else -1
        if idx < 0:
            return data
        pos = self._first_chunk_end(data)  # skip the document header chunk
        while pos + 8 <= len(data):
            chunk_type, _header_size, chunk_size = struct.unpack_from("<HHI", data, pos)
            if chunk_type != self._START_ELEMENT_TYPE:
                pos += chunk_size
                continue
            # START_ELEMENT: 16-byte header (type/size/line/comment), then the
            # 20-byte attrExt block (ns, name, attrStart, attrSize, attrCount),
            # then attribute records. attrStart is relative to attrExt.
            attr_count = struct.unpack_from("<H", data, pos + 28)[0]
            attr_start_rel = struct.unpack_from("<H", data, pos + 24)[0]
            attr_base = pos + 16 + attr_start_rel
            for i in range(attr_count):
                base = attr_base + i * 20
                _ns, name_idx, _raw_idx, typed_value, _value = struct.unpack_from("<IIIII", data, base)
                if name_idx == idx and (typed_value >> 24) == 0x10:  # INT_DEC
                    struct.pack_into("<I", data, base + 16, version_code & 0xFFFFFFFF)
                    return data
            break
        return data

    def _first_chunk_end(self, data: bytes) -> int:
        # The outer chunk is the XML document header (type 0x0003) spanning
        # the whole file; the real chunk stream (string pool, elements) starts
        # right after its 8-byte header.
        if len(data) < 8:
            return len(data)
        chunk_type, _hs, _size = struct.unpack_from("<HHI", data, 0)
        if chunk_type != self._RES_XML_TYPE:
            return 0
        return 8

    def _string_pool(self, data: bytes) -> list:
        """Parse the global UTF-16 string pool (type 0x0001) into Python strs."""
        pos = self._first_chunk_end(data)
        if pos + 8 > len(data):
            return []
        chunk_type, _hs, size = struct.unpack_from("<HHI", data, pos)
        if chunk_type != 0x0001:
            return []
        (string_count, _style_count, _flags, strings_start, _styles_start) = struct.unpack_from(
            "<IIIII", data, pos + 8
        )
        base = pos + strings_start
        offsets = struct.unpack_from(f"<{string_count}I", data, pos + 28)
        out = []
        for off in offsets:
            start = base + off
            if start + 2 > len(data):
                break
            (u16len,) = struct.unpack_from("<H", data, start)
            if u16len & 0x8000:  # high bit = length spans two units
                u16len = ((u16len & 0x7FFF) << 16) | struct.unpack_from("<H", data, start + 2)[0]
                text_start = start + 4
            else:
                text_start = start + 2
            raw = data[text_start:text_start + u16len * 2]
            out.append(raw.decode("utf-16-le", errors="replace"))
        return out


ACTIVITY_JAVA = r"""
package w;
import android.Manifest;
import android.app.Activity;
import android.app.DownloadManager;
import android.content.ClipData;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.SystemClock;
import android.provider.MediaStore;
import android.util.Base64;
import android.util.Log;
import android.graphics.Color;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.webkit.CookieManager;
import android.webkit.DownloadListener;
import android.webkit.GeolocationPermissions;
import android.webkit.JavascriptInterface;
import android.webkit.PermissionRequest;
import android.webkit.URLUtil;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.FrameLayout;
import android.widget.Toast;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;
public class M extends Activity {
    private static final int REQ_WRITE_STORAGE = 2001;
    private static final int REQ_LOCATION = 2002;
    private static final int REQ_MEDIA = 2003;
    private static final int REQ_FILE_CHOOSER = 2004;
    private static final int REQ_BRIDGE_STORAGE = 2005;
    private static final int REQ_NOTIFY = 2006;
    private static final String DESKTOP_USER_AGENT =
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        + "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

    // TV mode: WebView only grants fullscreen from a trusted user gesture, so
    // a scripted requestFullscreen() on playback is rejected. Inject a focused
    // fullscreen button instead: one OK press on the remote is a real gesture
    // and drives WebView's own fullscreen path (no ExoPlayer involved).
    private static final String TV_FULLSCREEN_JS =
        "(function(){"
        + "if(window.__wtaTvFsInstalled)return;"
        + "window.__wtaTvFsInstalled=true;"
        + "var style=document.createElement('style');"
        + "style.id='__wtaTvFsStyle';"
        + "style.textContent='#__wtaTvFsBtn{position:fixed;left:24px;top:24px;z-index:2147483647;background:rgba(0,0,0,.72);color:#fff;border:2px solid #ffb300;border-radius:8px;padding:8px 14px;font:16px sans-serif}';"
        + "if(document.head&&!document.getElementById('__wtaTvFsStyle'))document.head.appendChild(style);"
        + "var btn=document.createElement('button');"
        + "btn.type='button';btn.id='__wtaTvFsBtn';btn.textContent='全屏';"
        + "btn.onclick=function(){"
        + "var v=null;var all=document.querySelectorAll('video');"
        + "for(var i=0;i<all.length;i++){if(!all[i].paused&&!all[i].ended){v=all[i];break;}}"
        + "if(!v&&all.length)v=all[0];"
        + "if(!v)return;"
        + "if(v.requestFullscreen){var p=v.requestFullscreen();if(p&&p.catch)p.catch(function(e){});}"
        + "else if(v.webkitRequestFullscreen){v.webkitRequestFullscreen();}"
        + "};"
        + "btn.style.display='none';"
        + "(document.body||document.documentElement).appendChild(btn);"
        + "var fsShown=false;"
        + "var fsTimer=setInterval(function(){"
        + "var v=document.querySelector('video');"
        + "btn.style.display=v?'block':'none';"
        + "if(!v){fsShown=false;return;}"
        + "if(!fsShown){fsShown=true;btn.focus();}"
        + "try{if(window.WebToApp){var r=btn.getBoundingClientRect();"
        + "window.WebToApp.setFullscreenButtonRect("
        + "Math.round((r.left+r.width/2)*(window.devicePixelRatio||1)),"
        + "Math.round((r.top+r.height/2)*(window.devicePixelRatio||1)));}}catch(e){}"
        + "},300);"
        + "})();";

    // TV remote: give non-TV pages a visible focus cursor, geometric DPAD
    // navigation and media-key handling. Kept quote-simple like the script
    // above so the Java template needs no extra escaping.
    private static final String TV_REMOTE_JS =
        "(function(){"
        + "if(window.__wtaTvRemoteInstalled)return;"
        + "window.__wtaTvRemoteInstalled=true;"
        + "var s=document.createElement('style');"
        + "s.id='__wtaTvFocusStyle';"
        + "s.textContent=':focus{outline:3px solid #ffb300!important;outline-offset:2px!important}';"
        + "if(document.head&&!document.getElementById('__wtaTvFocusStyle'))document.head.appendChild(s);"
        + "var SEL='a,button,input,select,textarea,video,[tabindex],[role=button],[role=link],div,span,li';"
        + "var candidates=function(){"
        + "if(window.__wtaTvPadEl&&window.__wtaTvPadCandidates)return window.__wtaTvPadCandidates();"
        + "var m=(typeof window.__wtaTvFindModal==='function')?window.__wtaTvFindModal():null;"
        + "if(m){var mr=m.getBoundingClientRect();"
        + "if(mr.width>=window.innerWidth*0.85&&mr.height>=window.innerHeight*0.85)m=null;}"
        + "var nodes=m?m.querySelectorAll(SEL):document.querySelectorAll(SEL);"
        + "if(m&&!nodes.length)nodes=document.querySelectorAll(SEL);"
        + "var out=[];"
        + "for(var i=0;i<nodes.length;i++){"
        + "var el=nodes[i];"
        + "if(el.disabled||el.getAttribute('aria-hidden')==='true')continue;"
        + "var r=el.getBoundingClientRect();"
        + "if(r.width<4||r.height<4)continue;"
        + "var st=window.getComputedStyle(el);"
        + "if(st.visibility==='hidden'||st.display==='none'||st.opacity==='0')continue;"
        + "var base=el.matches('a,button,input,select,textarea,video,[tabindex],[role=button],[role=link]');"
        + "var pointer=st.cursor==='pointer'&&r.width<=320&&r.height<=320;"
        + "if(!base&&!pointer&&!el.onclick)continue;"
        + "var dup=false;for(var k=0;k<out.length;k++){if(out[k].el===el){dup=true;break;}}"
        + "if(dup)continue;"
        + "out.push({el:el,r:r});"
        + "}"
        + "return out;"
        + "};"
        + "var reportFocus=function(el){"
        + "try{if(window.WebToApp)window.WebToApp.setFocusIsFsBtn(!!(el&&el.id==='__wtaTvFsBtn'));}catch(e){}"
        + "};"
        + "var focusEl=function(el,noScroll){"
        + "try{if(el.tabIndex<0)el.setAttribute('tabindex','-1');}catch(e){}"
        + "el.focus();"
        + "reportFocus(el);"
        + "if(!noScroll){try{el.scrollIntoView({block:'center',inline:'center'});}catch(e){}}"
        + "};"
        + "try{document.addEventListener('focusin',function(e){reportFocus(e.target);},true);}catch(e){}"
        + "var topLeft=function(){"
        + "var l=candidates();if(!l.length)return null;"
        + "var fs=document.getElementById('__wtaTvFsBtn');"
        + "if(fs&&fs.style.display!=='none'&&document.querySelector('video'))return fs;"
        + "var best=0,score=Infinity;"
        + "for(var i=0;i<l.length;i++){"
        + "var r=l[i].r,s=r.top*2+r.left;"
        + "if(s<score){score=s;best=i;}"
        + "}"
        + "return l[best].el;"
        + "};"
        + "var resetFocus=function(){var el=topLeft();if(el)focusEl(el,true);};"
        + "var initial=document.activeElement;"
        + "if(initial&&initial.id==='__wtaTvFsBtn'&&initial.style.display!=='none'){reportFocus(initial);}"
        + "else{resetFocus();}"
        + "var hrefKey=function(){return location.pathname+location.search;};"
        + "var lastKey=hrefKey();"
        + "var checkHref=function(){var k=hrefKey();if(k!==lastKey){lastKey=k;resetFocus();}};"
        + "try{window.addEventListener('popstate',checkHref,false);}catch(e){}"
        + "var hrefTimer=setInterval(checkHref,400);"
        + "window.__wtaTvMoveFocus=function(dx,dy){"
        + "var list=candidates();if(!list.length)return;"
        + "var cur=document.activeElement,idx=-1;"
        + "for(var i=0;i<list.length;i++){if(list[i].el===cur){idx=i;break;}}"
        + "if(idx<0){resetFocus();return;}"
        + "var cr=list[idx].r,cx=cr.left+cr.width/2,cy=cr.top+cr.height/2;"
        + "var aligned=[],loose=[];"
        + "for(var j=0;j<list.length;j++){"
        + "if(j===idx)continue;"
        + "var r=list[j].r,nx=r.left+r.width/2,ny=r.top+r.height/2;"
        + "var main=(dx!==0)?(nx-cx)*dx:(ny-cy)*dy;"
        + "if(main<=8)continue;"
        + "var cross=(dx!==0)?Math.abs(ny-cy):Math.abs(nx-cx);"
        + "var tol=(dx!==0)?Math.max(cr.height,r.height)/2:Math.max(cr.width,r.width)/2;"
        + "var it={j:j,main:main,cross:cross};"
        + "if(cross<=tol)aligned.push(it);"
        + "loose.push(it);"
        + "}"
        + "var pool=aligned.length?aligned:loose;"
        + "if(!pool.length)return;"
        + "var pick=pool[0];"
        + "for(var k=1;k<pool.length;k++){"
        + "var b=pool[k];"
        + "if(b.main<pick.main||(b.main===pick.main&&b.cross<pick.cross))pick=b;"
        + "}"
        + "focusEl(list[pick.j].el);"
        + "};"
        + "window.__wtaTvActivate=function(){"
        + "var el=document.activeElement;"
        + "if(!el||el===document.body||el===document.documentElement)return;"
        + "if(window.__wtaTvOpenPad&&window.__wtaTvOpenPad(el))return;"
        + "try{el.click();}catch(e){}"
        + "};"
        + "window.__wtaTvMedia=function(action){"
        + "var v=null;"
        + "var fs=document.fullscreenElement||document.webkitFullscreenElement;"
        + "if(fs){v=(fs.tagName==='VIDEO')?fs:fs.querySelector('video');}"
        + "if(!v){var all=document.querySelectorAll('video');"
        + "for(var i=0;i<all.length;i++){if(!all[i].paused&&!all[i].ended){v=all[i];break;}}}"
        + "if(!v){var list=document.querySelectorAll('video');if(list.length)v=list[0];}"
        + "if(!v)return;"
        + "var dur=isFinite(v.duration)?v.duration:Infinity;"
        + "try{"
        + "if(action==='toggle'){if(v.paused)v.play();else v.pause();}"
        + "else if(action==='play'){v.play();}"
        + "else if(action==='pause'){v.pause();}"
        + "else if(action==='ff'){v.currentTime=Math.min(dur,v.currentTime+10);}"
        + "else if(action==='rw'){v.currentTime=Math.max(0,v.currentTime-10);}"
        + "else if(action==='next'){v.currentTime=Math.min(dur,v.currentTime+30);}"
        + "else if(action==='prev'){v.currentTime=Math.max(0,v.currentTime-30);}"
        + "else if(action==='stop'){v.pause();v.currentTime=0;}"
        + "}catch(e){}"
        + "};"
        + "})();";

    // TV subtitles: expose a CC button and a captions-key panel built from
    // the current video's textTracks (or hls.js subtitleTracks). Selection
    // uses standard Web APIs only; no assumption about the site's own player
    // chrome is required.
    private static final String TV_SUBTITLES_JS =
        "(function(){"
        + "if(window.__wtaTvSubsInstalled)return;"
        + "window.__wtaTvSubsInstalled=true;"
        + "var panel=null,btn=null;"
        + "var style=document.createElement('style');"
        + "style.id='__wtaTvSubsStyle';"
        + "style.textContent='#__wtaTvSubsBtn{position:fixed;right:24px;top:24px;z-index:2147483647;background:rgba(0,0,0,.72);color:#fff;border:2px solid #ffb300;border-radius:8px;padding:8px 14px;font:16px sans-serif}'"
        + "+'#__wtaTvSubsPanel{position:fixed;right:24px;top:80px;z-index:2147483647;background:rgba(0,0,0,.86);color:#fff;padding:16px 18px;border-radius:10px;font:16px/1.4 sans-serif;min-width:230px}'"
        + "+'#__wtaTvSubsPanel button{display:block;width:100%;margin:6px 0;background:transparent;color:#fff;border:1px solid #888;border-radius:6px;padding:8px 10px;text-align:left;font:16px sans-serif}'"
        + "+'#__wtaTvSubsPanel button[aria-pressed=true]{background:#ffb300;color:#111}';"
        + "if(document.head&&!document.getElementById('__wtaTvSubsStyle'))document.head.appendChild(style);"
        + "var activeVideo=function(){"
        + "var fs=document.fullscreenElement||document.webkitFullscreenElement;"
        + "if(fs){var v=(fs.tagName==='VIDEO')?fs:fs.querySelector('video');if(v)return v;}"
        + "var all=document.querySelectorAll('video');"
        + "for(var i=0;i<all.length;i++){if(!all[i].paused&&!all[i].ended&&all[i].readyState)return all[i];}"
        + "return all.length?all[0]:null;"
        + "};"
        + "var hlsOf=function(v){"
        + "if(!v)return null;"
        + "var h=v.hls||window.hls;"
        + "return (h&&h.subtitleTracks)?h:null;"
        + "};"
        + "var buildItems=function(v){"
        + "var out=[];"
        + "var tt=v&&v.textTracks;"
        + "if(tt&&tt.length){"
        + "out.push({label:'关闭字幕',apply:function(){for(var i=0;i<tt.length;i++){try{tt[i].mode='disabled';}catch(e){}}}});"
        + "for(var i=0;i<tt.length;i++){(function(idx){var t=tt[idx];out.push({label:(t.label||t.language||('轨道 '+(idx+1))),apply:function(){for(var j=0;j<tt.length;j++){try{tt[j].mode=(j===idx)?'showing':'disabled';}catch(e){}}}});})(i);}"
        + "return out;"
        + "}"
        + "var h=hlsOf(v);"
        + "if(h&&h.subtitleTracks.length){"
        + "out.push({label:'关闭字幕',apply:function(){try{h.subtitleTrack=-1;h.subtitleDisplay=false;}catch(e){}}});"
        + "for(var i=0;i<h.subtitleTracks.length;i++){(function(idx){var t=h.subtitleTracks[idx];out.push({label:(t.name||t.lang||('轨道 '+(idx+1))),apply:function(){try{h.subtitleDisplay=true;h.subtitleTrack=idx;}catch(e){}}});})(i);}"
        + "}"
        + "return out;"
        + "};"
        + "var render=function(){"
        + "var old=document.getElementById('__wtaTvSubsPanel');"
        + "if(old&&old.parentNode)old.parentNode.removeChild(old);"
        + "panel=document.createElement('div');panel.id='__wtaTvSubsPanel';"
        + "var head=document.createElement('div');head.textContent='字幕';head.style.marginBottom='8px';panel.appendChild(head);"
        + "var items=buildItems(activeVideo());"
        + "if(!items.length){var none=document.createElement('div');none.textContent='未检测到字幕轨道';panel.appendChild(none);}"
        + "for(var i=0;i<items.length;i++){(function(idx){var b=document.createElement('button');b.type='button';b.textContent=items[idx].label;b.setAttribute('aria-pressed','false');b.onclick=function(){items[idx].apply();btn.textContent=(idx===0?'CC':'CC ON');var list=panel.querySelectorAll('button');for(var j=0;j<list.length;j++){list[j].setAttribute('aria-pressed',(j===idx)?'true':'false');}};panel.appendChild(b);})(i);}"
        + "(document.body||document.documentElement).appendChild(panel);"
        + "var first=panel.querySelector('button');if(first)first.focus();"
        + "};"
        + "window.__wtaTvSubtitles=function(){"
        + "if(panel&&panel.parentNode){panel.parentNode.removeChild(panel);panel=null;return;}"
        + "render();"
        + "};"
        + "var installButton=function(){"
        + "if(document.getElementById('__wtaTvSubsBtn'))return;"
        + "btn=document.createElement('button');btn.type='button';btn.id='__wtaTvSubsBtn';btn.textContent='CC';"
        + "btn.style.display='none';"
        + "btn.onclick=function(){window.__wtaTvSubtitles();};"
        + "(document.body||document.documentElement).appendChild(btn);"
        + "};"
        + "installButton();"
        + "window.addEventListener('load',installButton,false);"
        + "var subTimer=setInterval(function(){"
        + "var v=activeVideo();"
        + "var nativeSubs=!!(v&&v.textTracks&&v.textTracks.length);"
        + "btn.style.display=(v&&!nativeSubs)?'block':'none';"
        + "if(!v&&panel&&panel.parentNode){panel.parentNode.removeChild(panel);panel=null;}"
        + "},300);"
        + "})();";

    // TV back key. Dismiss in-page modals (login / dialogs) first; otherwise
    // ask native code to perform a browser back. The activity always consumes
    // BACK in TV mode, so a page can never accidentally finish the app.
    private static final String TV_BACK_JS =
        "(function(){"
        + "if(window.__wtaTvBackInstalled)return;"
        + "window.__wtaTvBackInstalled=true;"
        + "var shown=function(el,minW,minH){"
        + "if(!el)return false;"
        + "var st=window.getComputedStyle(el);var r=el.getBoundingClientRect();"
        + "return !!st&&st.display!=='none'&&st.visibility!=='hidden'&&st.opacity!=='0'&&r.width>=minW&&r.height>=minH;"
        + "};"
        + "var isModal=function(el){"
        + "if(!shown(el,120,80))return false;"
        + "var st=window.getComputedStyle(el);"
        + "var z=parseInt(st.zIndex,10);if(isNaN(z))z=0;"
        + "return (st.position==='fixed'||st.position==='absolute')&&z>=50;"
        + "};"
        + "var findModal=function(){"
        + "var sels=['[aria-modal=true]','[role=dialog]','[class*=modal]','[class*=Modal]','[class*=dialog]','[class*=Dialog]','[class*=popup]','[class*=Popup]','[class*=mask]','[class*=Mask]'];"
        + "var best=null,area=Infinity;"
        + "for(var i=0;i<sels.length;i++){"
        + "var ns=document.querySelectorAll(sels[i]);"
        + "for(var j=0;j<ns.length;j++){"
        + "if(!isModal(ns[j]))continue;"
        + "var r=ns[j].getBoundingClientRect();var a=r.width*r.height;"
        + "if(a<area){area=a;best=ns[j];}"
        + "}"
        + "}"
        + "if(best)return best;"
        + "var all=document.querySelectorAll('body *');"
        + "var vw=window.innerWidth,vh=window.innerHeight;"
        + "for(var k=0;k<all.length;k++){"
        + "var e=all[k],st=window.getComputedStyle(e),r=e.getBoundingClientRect();"
        + "if(st.display==='none'||st.visibility==='hidden'||st.opacity==='0')continue;"
        + "var z=parseInt(st.zIndex,10);if(isNaN(z)||z<50)continue;"
        + "if(st.position!=='fixed'&&st.position!=='absolute')continue;"
        + "if(r.width<vw*0.45||r.height<vh*0.45)continue;"
        + "var a2=r.width*r.height;if(a2<area){area=a2;best=e;}"
        + "}"
        + "return best;"
        + "};"
        + "var esc=function(){"
        + "try{var o={key:'Escape',code:'Escape',keyCode:27,which:27,bubbles:true,cancelable:true};"
        + "document.dispatchEvent(new KeyboardEvent('keydown',o));"
        + "window.dispatchEvent(new KeyboardEvent('keydown',o));"
        + "document.dispatchEvent(new KeyboardEvent('keyup',o));"
        + "window.dispatchEvent(new KeyboardEvent('keyup',o));}catch(e){}"
        + "};"
        + "var closeLike=function(e){"
        + "if(!shown(e,4,4))return false;"
        + "var r=e.getBoundingClientRect();if(r.width>90||r.height>90)return false;"
        + "var meta=(e.getAttribute('aria-label')||'')+' '+(e.getAttribute('title')||'')+' '+(e.className||'');"
        + "var txt=(e.textContent||'').trim();"
        + "return /close|关闭|取消|dismiss/i.test(meta)||/^(×|✕|✖|x|关闭|取消)$/i.test(txt);"
        + "};"
        + "var findClose=function(dlg){"
        + "var ns=(dlg||document).querySelectorAll('button,[role=button],a,span,div,i');"
        + "for(var k=0;k<ns.length;k++){if(closeLike(ns[k]))return ns[k];}"
        + "if(dlg){"
        + "var all=document.querySelectorAll('button,[role=button],a,span,div,i');"
        + "for(var m=0;m<all.length;m++){if(closeLike(all[m]))return all[m];}"
        + "}"
        + "return null;"
        + "};"
        + "var log=function(m){try{if(window.WebToApp)window.WebToApp.logBack(m);}catch(e){}};"
        + "var touch=function(el){"
        + "if(!el)return;"
        + "try{var r=el.getBoundingClientRect();var x=r.left+r.width/2,y=r.top+r.height/2;"
        + "var o={bubbles:true,cancelable:true,clientX:x,clientY:y};"
        + "el.dispatchEvent(new MouseEvent('mousedown',o));"
        + "el.dispatchEvent(new MouseEvent('mouseup',o));}catch(e){}"
        + "try{el.click();}catch(e){}"
        + "};"
        + "var sigOf=function(dlg){"
        + "var r=dlg.getBoundingClientRect();"
        + "var cls=String(dlg.className||'').slice(0,40);"
        + "return Math.round(r.left)+':'+Math.round(r.top)+':'+Math.round(r.width)+':'+Math.round(r.height)+':'+cls;"
        + "};"
        + "var backdropOf=function(dlg){"
        + "var p=dlg.parentElement,vw=window.innerWidth,vh=window.innerHeight;"
        + "for(var i=0;i<4&&p;i++){"
        + "var r=p.getBoundingClientRect();"
        + "if(r.width>=vw*0.8&&r.height>=vh*0.8)return p;"
        + "p=p.parentElement;}"
        + "return null;"
        + "};"
        + "var closeAtCorner=function(dlg){"
        + "var r=dlg.getBoundingClientRect();"
        + "var pts=[[r.right-18,r.top+18],[r.right-18,r.top+44],[r.left+18,r.top+18],[r.right-18,r.bottom-18]];"
        + "for(var i=0;i<pts.length;i++){"
        + "var el=document.elementFromPoint(pts[i][0],pts[i][1]);"
        + "if(el&&dlg.contains(el)){touch(el);return true;}}"
        + "return false;"
        + "};"
        + "var state={sig:'',tries:0};"
        + "window.__wtaTvFindModal=findModal;"
        + "window.__wtaTvBack=function(){"
        + "if(window.__wtaTvClosePad&&window.__wtaTvClosePad()){log('pad-close');return;}"
        + "var dlg=findModal();"
        + "if(!dlg){state.sig='';state.tries=0;log('no-modal');"
        + "try{if(window.WebToApp)window.WebToApp.performBack(location.href);}catch(e){}return;}"
        + "var fr=dlg.getBoundingClientRect();"
        + "if(fr.width>=window.innerWidth*0.7&&fr.height>=window.innerHeight*0.7){log('modal-page');esc();try{window.history.back();}catch(e){}return;}"
        + "var sig=sigOf(dlg);"
        + "if(sig!==state.sig){state.sig=sig;state.tries=0;}"
        + "state.tries++;"
        + "if(state.tries===1){var c=findClose(dlg);log(c?'modal-close':'modal-esc');if(c)touch(c);esc();return;}"
        + "if(state.tries===2){log('modal-corner');if(!closeAtCorner(dlg)){var b=backdropOf(dlg);if(b)touch(b);}esc();return;}"
        + "if(state.tries===3){log('modal-history');esc();try{window.history.back();}catch(e){}return;}"
        + "log('modal-giveup');state.sig='';state.tries=0;esc();"
        + "try{if(window.WebToApp)window.WebToApp.performBack(location.href);}catch(e){}"
        + "};"
        + "})();";

    // TV text input. A TV remote cannot drive the system IME: the login page's
    // phone / verification-code fields become focusable but unusable. Focusing
    // such a field opens an injected numeric keypad that DPAD can operate, and
    // writes through the page's native value setter so React/Vue state updates.
    private static final String TV_INPUT_JS =
        "(function(){"
        + "if(window.__wtaTvPadInstalled)return;"
        + "window.__wtaTvPadInstalled=true;"
        + "var pad=null,target=null;"
        + "var canPad=function(el){"
        + "if(!el||!el.tagName)return false;"
        + "var tag=el.tagName.toLowerCase();"
        + "if(tag!=='input'&&tag!=='textarea')return false;"
        + "var t=(el.getAttribute('type')||'').toLowerCase();"
        + "if(t==='tel'||t==='number')return true;"
        + "var ph=(el.getAttribute('placeholder')||'')+' '+(el.getAttribute('name')||'');"
        + "if(/手机|电话|验证码|phone|code|mobile/i.test(ph))return true;"
        + "var ml=parseInt(el.getAttribute('maxlength'),10);"
        + "if(!isNaN(ml)&&ml>0&&ml<=11)return true;"
        + "return false;"
        + "};"
        + "var setVal=function(el,v){"
        + "try{var d=Object.getOwnPropertyDescriptor(el.constructor.prototype,'value');"
        + "if(d&&d.set)d.set.call(el,v);else el.value=v;}catch(e){try{el.value=v;}catch(x){}}"
        + "try{if(el._valueTracker)el._valueTracker.setValue('');}catch(e){}"
        + "try{el.dispatchEvent(new Event('input',{bubbles:true}));}catch(e){}"
        + "try{el.dispatchEvent(new Event('change',{bubbles:true}));}catch(e){}"
        + "};"
        + "var close=function(){"
        + "var e=target;"
        + "if(pad&&pad.parentNode)pad.parentNode.removeChild(pad);"
        + "pad=null;target=null;window.__wtaTvPadEl=null;"
        + "try{if(e&&document.body&&document.body.contains(e))e.focus();}catch(x){}"
        + "};"
        + "var refresh=function(){"
        + "var v=pad?pad.querySelector('#__wtaTvPadVal'):null;"
        + "if(v&&target)v.textContent=(target.value||'').slice(-16);"
        + "};"
        + "var key=function(txt,act){"
        + "var b=document.createElement('button');b.type='button';b.textContent=txt;"
        + "b.style.cssText='min-width:64px;height:54px;margin:3px;font:20px sans-serif;border-radius:8px;border:1px solid #666;background:#222;color:#fff';"
        + "b.onclick=function(){try{act();}catch(e){}refresh();};"
        + "return b;"
        + "};"
        + "var open=function(el){"
        + "close();target=el;"
        + "pad=document.createElement('div');pad.id='__wtaTvPad';"
        + "pad.style.cssText='position:fixed;left:50%;bottom:24px;transform:translateX(-50%);z-index:2147483647;background:rgba(0,0,0,.92);padding:10px 12px;border-radius:12px;border:1px solid #555';"
        + "var h=document.createElement('div');h.id='__wtaTvPadVal';"
        + "h.style.cssText='color:#ffb300;font:18px sans-serif;text-align:center;margin-bottom:6px;min-height:20px';"
        + "pad.appendChild(h);"
        + "var g=document.createElement('div');g.style.cssText='display:grid;grid-template-columns:repeat(5,auto)';"
        + "var digits='1234567890';"
        + "for(var i=0;i<digits.length;i++){(function(d){"
        + "g.appendChild(key(d,function(){target&&setVal(target,(target.value||'')+d);}));"
        + "})(digits.charAt(i));}"
        + "g.appendChild(key('删除',function(){target&&setVal(target,(target.value||'').slice(0,-1));}));"
        + "g.appendChild(key('清空',function(){target&&setVal(target,'');}));"
        + "g.appendChild(key('完成',function(){close();}));"
        + "pad.appendChild(g);"
        + "(document.body||document.documentElement).appendChild(pad);"
        + "window.__wtaTvPadEl=pad;"
        + "var first=pad.querySelector('button');if(first)first.focus();"
        + "refresh();"
        + "};"
        + "window.__wtaTvOpenPad=function(el){if(!canPad(el))return false;open(el);return true;};"
        + "window.__wtaTvClosePad=function(){if(!pad)return false;close();return true;};"
        + "window.__wtaTvPadCandidates=function(){"
        + "var out=[];if(!pad)return out;"
        + "var bs=pad.querySelectorAll('button');"
        + "for(var i=0;i<bs.length;i++){out.push({el:bs[i],r:bs[i].getBoundingClientRect()});}"
        + "return out;"
        + "};"
        + "})();";

    // Core ad/tracker network blocklist. Stored as a HashSet for O(1) lookups.
    // Subdomain matching is handled in isAdHost() — adding "doubleclick.net"
    // automatically blocks "securepubads.g.doubleclick.net" etc.
    private static final Set<String> AD_HOSTS = new HashSet<>(Arrays.asList(
        "doubleclick.net",
        "googlesyndication.com",
        "adservice.google.com",
        "amazon-adsystem.com",
        "ads.yahoo.com",
        "googletagmanager.com",
        "googletagservices.com",
        "adnxs.com",
        "adsystem.amazon.com",
        "pagead2.googlesyndication.com",
        "tpc.googlesyndication.com",
        "securepubads.g.doubleclick.net",
        "pubads.g.doubleclick.net",
        "ads.rubiconproject.com",
        "pixel.rubiconproject.com",
        "ib.adnxs.com",
        "cdn.taboola.com",
        "trc.taboola.com",
        "cdn.outbrain.com",
        "widgets.outbrain.com",
        "popads.net",
        "popcash.net",
        "juicyads.com",
        "exoclick.com",
        "trafficjunky.net",
        "adsterra.com",
        "hilltopads.net",
        "propellerads.com",
        "adcash.com",
        "revcontent.com",
        "mgid.com",
        "trafficfactory.biz"
    ));

    private WebView webView;
    private WebAppBridge webBridge;
    private AppConfig config;
    private PendingDownload pendingDownload;
    private GeolocationPermissions.Callback pendingGeolocationCallback;
    private String pendingGeolocationOrigin;
    private String homeUrl;
    private PermissionRequest pendingPermissionRequest;
    private ValueCallback<Uri[]> pendingFileChoiceCallback;
    private FrameLayout fullscreenContainer;
    private android.widget.Button fullscreenExitButton;
    private View customView;
    private WebChromeClient.CustomViewCallback customViewCallback;

    /**
     * Returns true if the given host matches any blocked ad/tracker domain.
     * Checks direct match first (O(1)), then walks up the subdomain chain so
     * that e.g. "sub.doubleclick.net" is caught by the "doubleclick.net" entry.
     * Also checks any extra hosts supplied at runtime via webtoapp_config.json.
     */
    private boolean isAdHost(String host) {
        if (host == null || host.isEmpty()) return false;
        String lower = host.toLowerCase(Locale.US);
        if (AD_HOSTS.contains(lower)) return true;
        int dot = lower.indexOf('.');
        while (dot != -1) {
            String parent = lower.substring(dot + 1);
            if (AD_HOSTS.contains(parent)) return true;
            dot = lower.indexOf('.', dot + 1);
        }
        // Check server-supplied extra hosts from webtoapp_config.json
        if (config != null && config.extraAdHosts.contains(lower)) return true;
        return false;
    }

    /** Returns an empty 200 response to silently swallow a blocked request.
     *  The page never sees a network error — the request just yields nothing. */
    private WebResourceResponse emptyResponse() {
        return new WebResourceResponse(
            "text/plain", "utf-8",
            new ByteArrayInputStream(new byte[0])
        );
    }

    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().requestFeature(android.view.Window.FEATURE_NO_TITLE);
        config = loadConfig();
        webView = new WebView(this);
        webView.setFocusable(true);
        webView.setFocusableInTouchMode(true);
        webView.requestFocus();
        applyImmersiveMode();
        webView.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                return handleNavigation(request != null && request.getUrl() != null ? request.getUrl().toString() : null);
            }
            @Override public boolean shouldOverrideUrlLoading(WebView view, String url) {
                return handleNavigation(url);
            }
            @Override public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                // shouldOverrideUrlLoading is not called for server-side
                // redirects, so re-check the landed host in TV mode.
                if (config != null && config.tvMode) {
                    Log.d("WebToAppTV", "onPageFinished url=" + url
                            + " allowed=" + isAllowedNavigationHost(url)
                            + " startHost=" + config.startHost);
                }
                if (config != null && config.tvMode
                        && url != null
                        && (url.startsWith("http://") || url.startsWith("https://"))
                        && !isAllowedNavigationHost(url)) {
                    toastOnUi("已拦截站外跳转");
                    if (view.canGoBack()) view.goBack();
                    else if (config.url != null) view.loadUrl(config.url);
                    return;
                }
                if (config != null && config.tvMode && config.tvAutoFullscreen) {
                    view.evaluateJavascript(TV_FULLSCREEN_JS, null);
                }
                if (config != null && config.tvMode && config.tvRemote) {
                    view.evaluateJavascript(TV_REMOTE_JS, null);
                }
                if (config != null && config.tvMode && config.tvSubtitles) {
                    view.evaluateJavascript(TV_SUBTITLES_JS, null);
                }
                if (config != null && config.tvMode) {
                    // BACK handling is independent of the remote/toggle options.
                    view.evaluateJavascript(TV_BACK_JS, null);
                }
                if (config != null && config.tvMode) {
                    // On-screen keypad: keyboard-free entry for phone / code fields.
                    view.evaluateJavascript(TV_INPUT_JS, null);
                }
                if (config != null && config.tvMode && homeUrl == null
                        && url != null
                        && (url.startsWith("http://") || url.startsWith("https://"))
                        && isAllowedNavigationHost(url)) {
                    int q = url.indexOf('?');
                    homeUrl = q > 0 ? url.substring(0, q) : url;
                }
            }
            // ── Ad blocker (modern API 21+) ───────────────────────────────
            // Intercepts every sub-resource request. Ad network hosts get an
            // empty 200 back; everything else passes through untouched.
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view, WebResourceRequest request) {
                if (request != null && request.getUrl() != null) {
                    if (isAdHost(request.getUrl().getHost())) {
                        return emptyResponse();
                    }
                    // Desktop mode: force a desktop-size layout viewport.
                    // A site's <meta name="viewport" content="width=device-width">
                    // pins the layout viewport to the phone width, so responsive
                    // pages render the mobile layout even when the user agent is
                    // desktop. Chrome's "request desktop site" uses a ~980px
                    // viewport, but WebView has no public API for that, so for the
                    // main-frame document we strip the viewport meta from the HTML
                    // before it is parsed. Without the meta the layout viewport
                    // falls back to the wide desktop viewport.
                    if (config != null && config.desktopMode
                            && request.isForMainFrame()
                            && "GET".equalsIgnoreCase(request.getMethod())
                            && ("http".equals(request.getUrl().getScheme())
                                || "https".equals(request.getUrl().getScheme()))) {
                        try {
                            WebResourceResponse desktop = desktopHtml(request.getUrl().toString());
                            if (desktop != null) return desktop;
                        } catch (Throwable ignored) {}
                    }
                }
                return super.shouldInterceptRequest(view, request);
            }
            // ── Ad blocker (legacy pre-API 21) ────────────────────────────
            @Override
            public WebResourceResponse shouldInterceptRequest(WebView view, String url) {
                if (url != null) {
                    try {
                        if (isAdHost(Uri.parse(url).getHost())) {
                            return emptyResponse();
                        }
                    } catch (Throwable ignored) {}
                }
                return super.shouldInterceptRequest(view, url);
            }
            // ─────────────────────────────────────────────────────────────
        });
        webView.setWebChromeClient(new AppChromeClient());
        webView.setDownloadListener(new AppDownloadListener());
        webBridge = new WebAppBridge();
        webView.addJavascriptInterface(webBridge, "WebToApp");
        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setDatabaseEnabled(true);
        s.setAllowContentAccess(true);
        s.setAllowFileAccess(false);
        s.setJavaScriptCanOpenWindowsAutomatically(true);
        s.setMediaPlaybackRequiresUserGesture(false);
        s.setGeolocationEnabled(true);
        s.setLoadWithOverviewMode(true);
        s.setUseWideViewPort(true);
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
            s.setMixedContentMode(WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE);
        }
        String ua = s.getUserAgentString();
        if (ua != null && !ua.isEmpty()) {
            s.setUserAgentString(config.desktopMode ? DESKTOP_USER_AGENT : sanitizeUserAgent(ua));
        }
        try {
            CookieManager cm = CookieManager.getInstance();
            cm.setAcceptCookie(true);
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.LOLLIPOP) {
                cm.setAcceptThirdPartyCookies(webView, true);
            }
        } catch (Throwable ignored) {}
        try {
            String launchUrl = config.url != null && !config.url.isEmpty() ? config.url : "about:blank";
            webView.loadUrl(launchUrl);
        } catch (Exception e) { webView.loadUrl("about:blank"); }
        setContentView(webView);
        applyImmersiveMode();
    }

    private String sanitizeUserAgent(String ua) {
        return ua.replace("; wv", "").replace(" Version/4.0", "");
    }

    /**
     * Desktop mode helper. Fetches the main-frame document over the desktop
     * user agent and returns it with any viewport meta tag removed, so the
     * layout viewport falls back to the wide (~980px) desktop viewport.
     * Response headers (Set-Cookie, Cache-Control, ...) are passed through so
     * sessions and caching behave like a normal request. Returns null on any
     * failure so the caller falls back to the default WebView request.
     */
    private WebResourceResponse desktopHtml(String url) {
        java.net.HttpURLConnection conn = null;
        try {
            conn = (java.net.HttpURLConnection) new java.net.URL(url).openConnection();
            conn.setInstanceFollowRedirects(true);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);
            conn.setRequestProperty("User-Agent", DESKTOP_USER_AGENT);
            String cookies = CookieManager.getInstance().getCookie(url);
            if (cookies != null && !cookies.isEmpty()) {
                conn.setRequestProperty("Cookie", cookies);
            }
            int code = conn.getResponseCode();
            if (code < 200 || code >= 300) return null;
            java.io.InputStream in = conn.getInputStream();
            java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
            byte[] chunk = new byte[16384];
            int n;
            while ((n = in.read(chunk)) != -1) buf.write(chunk, 0, n);
            in.close();
            String contentType = conn.getContentType();
            String charset = "utf-8";
            if (contentType != null) {
                java.util.regex.Matcher cm = java.util.regex.Pattern
                    .compile("charset=([^;\\s]+)", java.util.regex.Pattern.CASE_INSENSITIVE)
                    .matcher(contentType);
                if (cm.find()) charset = cm.group(1).replace("\"", "").trim();
            }
            String html = new String(buf.toByteArray(), charset);
            html = html.replaceAll(
                "(?is)<meta\\b[^>]*\\bname\\s*=\\s*[\"']?viewport[\"']?[^>]*>", "");
            java.util.Map<String, String> headers = new java.util.HashMap<>();
            for (java.util.Map.Entry<String, java.util.List<String>> e : conn.getHeaderFields().entrySet()) {
                if (e.getKey() != null && e.getValue() != null && !e.getValue().isEmpty()) {
                    headers.put(e.getKey(), e.getValue().get(0));
                }
            }
            return new WebResourceResponse("text/html", charset, code, "OK", headers,
                new ByteArrayInputStream(html.getBytes(charset)));
        } catch (Throwable e) {
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private AppConfig loadConfig() {
        AppConfig loaded = new AppConfig();
        try {
            InputStream input = getAssets().open("webtoapp_config.json");
            // readAllBytes() only exists on API 33+; using it here made every
            // config load fail on API 21-32 and left the app on about:blank.
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[4096];
            int count;
            while ((count = input.read(chunk)) != -1) {
                buffer.write(chunk, 0, count);
            }
            input.close();
            byte[] data = buffer.toByteArray();
            JSONObject json = new JSONObject(new String(data, StandardCharsets.UTF_8));
            loaded.url = json.optString("url", "about:blank").trim();
            loaded.immersiveFullscreen = json.optBoolean("immersive_fullscreen", false);
            loaded.desktopMode = json.optBoolean("desktop_mode", false);
            // Load any extra ad hosts supplied by the server at build time
            JSONArray extraHosts = json.optJSONArray("extra_ad_hosts");
            if (extraHosts != null) {
                for (int i = 0; i < extraHosts.length(); i++) {
                    String h = extraHosts.optString(i, "").trim().toLowerCase(Locale.US);
                    if (!h.isEmpty()) loaded.extraAdHosts.add(h);
                }
            }
            loaded.tvMode = json.optBoolean("tv_mode", false);
            loaded.tvAutoFullscreen = json.optBoolean("tv_auto_fullscreen", false);
            loaded.tvRemote = json.optBoolean("tv_remote", false);
            loaded.tvSubtitles = json.optBoolean("tv_subtitles", false);
            JSONArray tvHosts = json.optJSONArray("tv_nav_hosts");
            if (tvHosts != null) {
                for (int i = 0; i < tvHosts.length(); i++) {
                    String h = tvHosts.optString(i, "").trim().toLowerCase(Locale.US);
                    if (!h.isEmpty()) loaded.tvNavHosts.add(h);
                }
            }
            if (loaded.url != null && !loaded.url.isEmpty()) {
                try { loaded.startHost = Uri.parse(loaded.url).getHost(); } catch (Throwable ignored) {}
            }
            // Many sites redirect mobile WebView UAs between www./m./bare
            // hosts. Treat those as the same site so TV mode does not bounce
            // back to the start URL in an endless "off-site" loop.
            if (loaded.tvMode && loaded.startHost != null) {
                String host = loaded.startHost.toLowerCase(Locale.US);
                String bare = host;
                if (bare.startsWith("www.")) bare = bare.substring(4);
                else if (bare.startsWith("m.")) bare = bare.substring(2);
                if (!bare.isEmpty()) loaded.tvNavHosts.add(bare);
            }
        } catch (Throwable ignored) {}
        return loaded;
    }

    private void applyImmersiveMode() {
        if (config == null || !config.immersiveFullscreen) return;
        android.view.Window window = getWindow();
        // Draw behind the system bars so content fills the whole screen with no
        // black letterbox where the status/navigation bars used to be.
        // API 35+ (targetSdk 35+) enforces edge-to-edge and IGNORES the legacy
        // setSystemUiVisibility flags, so those paths below are only for < 35.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            window.setDecorFitsSystemWindows(false);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA) {
            // targetSdk 35+: hide the bars entirely via WindowInsetsController and
            // pad the WebView by the transient-bar insets so content is never
            // drawn underneath the bars when the user swipes to reveal them.
            WindowInsetsController controller = window.getInsetsController();
            if (controller != null) {
                controller.hide(WindowInsets.Type.statusBars() | WindowInsets.Type.navigationBars());
                controller.setSystemBarsBehavior(WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE);
            }
            webView.setOnApplyWindowInsetsListener(new View.OnApplyWindowInsetsListener() {
                @Override public android.view.WindowInsets onApplyWindowInsets(View v, android.view.WindowInsets insets) {
                    android.graphics.Insets bars = insets.getInsets(
                        WindowInsets.Type.statusBars() | WindowInsets.Type.navigationBars()
                        | WindowInsets.Type.displayCutout());
                    v.setPadding(bars.left, bars.top, bars.right, bars.bottom);
                    return WindowInsets.CONSUMED;
                }
            });
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            WindowInsetsController controller = window.getInsetsController();
            if (controller != null) {
                controller.hide(WindowInsets.Type.statusBars() | WindowInsets.Type.navigationBars());
                controller.setSystemBarsBehavior(WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE);
            }
        } else {
            View decor = window.getDecorView();
            decor.setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                    | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                    | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                    | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                    | View.SYSTEM_UI_FLAG_FULLSCREEN
                    | View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
            );
        }
        // Extend into the display cutout (notch) area too, and make the bars
        // transparent so nothing shows through during the transient swipe.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            window.getAttributes().layoutInDisplayCutoutMode =
                android.view.WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_SHORT_EDGES;
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            window.setStatusBarColor(android.graphics.Color.TRANSPARENT);
            window.setNavigationBarColor(android.graphics.Color.TRANSPARENT);
        }
    }

    private boolean handleNavigation(String url) {
        if (url == null) return false;
        String trimmed = url.trim();
        if (trimmed.isEmpty()) return false;
        String lower = trimmed.toLowerCase(Locale.US);
        boolean tvMode = config != null && config.tvMode;
        if (lower.startsWith("http://") || lower.startsWith("https://")) {
            // false = let the WebView load it; true = block it. TV mode only
            // allows the launch host plus explicitly configured extra hosts.
            return tvMode && !isAllowedNavigationHost(trimmed);
        }
        if (
            lower.startsWith("about:") ||
            lower.startsWith("javascript:") ||
            lower.startsWith("data:") ||
            lower.startsWith("blob:")
        ) {
            return false;
        }
        if (tvMode) return true;
        if (lower.startsWith("intent://")) {
            return openIntentUri(trimmed);
        }
        return openExternal(trimmed);
    }

    private static boolean isSameHostOrSubdomain(String host, String base) {
        if (host == null || base == null) return false;
        String h = host.toLowerCase(Locale.US);
        String b = base.toLowerCase(Locale.US);
        return h.equals(b) || h.endsWith("." + b);
    }

    private boolean isAllowedNavigationHost(String url) {
        if (url == null || config == null) return false;
        try {
            String host = Uri.parse(url).getHost();
            if (host == null || host.isEmpty()) return false;
            if (isSameHostOrSubdomain(host, config.startHost)) return true;
            for (String allowed : config.tvNavHosts) {
                if (isSameHostOrSubdomain(host, allowed)) return true;
            }
            return false;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private boolean openIntentUri(String url) {
        try {
            Intent intent = Intent.parseUri(url, Intent.URI_INTENT_SCHEME);
            String fallback = intent.getStringExtra("browser_fallback_url");
            intent.removeExtra("browser_fallback_url");
            intent.addCategory(Intent.CATEGORY_BROWSABLE);
            intent.setComponent(null);
            intent.setSelector(null);
            try {
                startActivity(intent);
                return true;
            } catch (Throwable ignored) {
                if (fallback != null && (fallback.startsWith("http://") || fallback.startsWith("https://"))) {
                    webView.loadUrl(fallback);
                    return true;
                }
            }
        } catch (Throwable ignored) {}
        return true;
    }

    private boolean openExternal(String url) {
        try {
            Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            intent.addCategory(Intent.CATEGORY_BROWSABLE);
            intent.setComponent(null);
            intent.setSelector(null);
            startActivity(intent);
        } catch (Throwable ignored) {}
        return true;
    }

    private final class AppChromeClient extends WebChromeClient {
        @Override public void onGeolocationPermissionsShowPrompt(String origin, GeolocationPermissions.Callback callback) {
            handleGeolocationPermission(origin, callback);
        }

        @Override public void onPermissionRequest(final PermissionRequest request) {
            runOnUiThread(new Runnable() {
                @Override public void run() {
                    handleMediaPermission(request);
                }
            });
        }

        @Override public void onPermissionRequestCanceled(PermissionRequest request) {
            if (pendingPermissionRequest == request) {
                pendingPermissionRequest = null;
            }
        }

        // ── HTML5 video fullscreen (TV mode) ──────────────────────────────
        // Without these callbacks requestFullscreen() is a no-op in WebView:
        // the video stays inline. Swap in a black fullscreen container and
        // restore the WebView when the player leaves fullscreen.
        @Override public void onShowCustomView(View view, CustomViewCallback callback) {
            if (customView != null) {
                callback.onCustomViewHidden();
                return;
            }
            if (fullscreenContainer == null) {
                fullscreenContainer = new FrameLayout(M.this);
                fullscreenContainer.setBackgroundColor(Color.BLACK);
                fullscreenExitButton = new android.widget.Button(M.this);
                fullscreenExitButton.setText("退出全屏");
                fullscreenExitButton.setTextColor(Color.WHITE);
                fullscreenExitButton.setBackgroundColor(Color.argb(150, 0, 0, 0));
                fullscreenExitButton.setFocusable(true);
                FrameLayout.LayoutParams exitLp = new FrameLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    android.view.Gravity.TOP | android.view.Gravity.LEFT);
                exitLp.setMargins(24, 24, 0, 0);
                fullscreenContainer.addView(fullscreenExitButton, exitLp);
                fullscreenExitButton.setOnClickListener(new View.OnClickListener() {
                    @Override public void onClick(View v) {
                        onHideCustomView();
                    }
                });
            }
            customView = view;
            customViewCallback = callback;
            if (view.getParent() != null) {
                ((ViewGroup) view.getParent()).removeView(view);
            }
            fullscreenContainer.addView(view, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.MATCH_PARENT));
            fullscreenExitButton.bringToFront();
            fullscreenContainer.setVisibility(View.VISIBLE);
            view.setFocusable(true);
            view.setFocusableInTouchMode(true);
            setContentView(fullscreenContainer);
            view.requestFocus();
        }

        @Override public void onHideCustomView() {
            if (customView == null) return;
            if (customViewCallback != null) {
                try { customViewCallback.onCustomViewHidden(); } catch (Throwable ignored) {}
            }
            if (fullscreenContainer != null) {
                fullscreenContainer.removeView(customView);
                fullscreenContainer.setVisibility(View.GONE);
            }
            customView = null;
            customViewCallback = null;
            setContentView(webView);
            applyImmersiveMode();
        }
        // ─────────────────────────────────────────────────────────────────

        // ── Popup blocker ─────────────────────────────────────────────────
        // Ad networks call window.open() without any user interaction to spawn
        // popup ads. We allow only windows that originated from a genuine user
        // gesture (e.g. a real link tap). Everything else is silently dropped.
        @Override
        public boolean onCreateWindow(WebView view, boolean isDialog,
                                      boolean isUserGesture, android.os.Message resultMsg) {
            return !isUserGesture;
        }
        // ─────────────────────────────────────────────────────────────────

        // ── File chooser (<input type="file">) ────────────────────────────
        // WebView ships no default file picker: without this override every
        // tap on an <input type="file"> silently does nothing. We hand the
        // request to the system picker via startActivityForResult and deliver
        // the result back in onActivityResult.
        @Override public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback,
                                                   FileChooserParams params) {
            // Settle any chooser still pending (e.g. the user backed out of a
            // previous one without cancelling cleanly). Leaving it hanging
            // makes WebView drop all future file-input taps.
            if (pendingFileChoiceCallback != null) {
                pendingFileChoiceCallback.onReceiveValue(null);
            }
            pendingFileChoiceCallback = callback;
            try {
                Intent intent = params.createIntent();
                if (params.getMode() == FileChooserParams.MODE_OPEN_MULTIPLE) {
                    intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
                }
                startActivityForResult(intent, REQ_FILE_CHOOSER);
                return true;
            } catch (Throwable ignored) {
                pendingFileChoiceCallback = null;
                return false;
            }
        }
        // ─────────────────────────────────────────────────────────────────
    }

    private final class AppDownloadListener implements DownloadListener {
        @Override public void onDownloadStart(String url, String userAgent, String contentDisposition, String mimeType, long contentLength) {
            String lower = url != null ? url.trim().toLowerCase(Locale.US) : "";
            String mime = mimeType != null ? mimeType : "";
            // Page-generated content never reaches a server, so DownloadManager
            // (http/https only) cannot fetch it. Resolve blobs inside the page
            // and decode data: URLs locally instead of failing silently.
            if (lower.startsWith("blob:")) {
                String name = sanitizeFileSegment(URLUtil.guessFileName(url, contentDisposition, mimeType));
                resolveBlobDownload(url, name, mime);
                return;
            }
            if (lower.startsWith("data:")) {
                byte[] data = decodeDataUrl(url);
                if (data == null) {
                    Log.w("WebToApp", "data: download undecodable");
                    toastOnUi("导出失败，请重试");
                } else {
                    String name = sanitizeFileSegment(URLUtil.guessFileName(url, contentDisposition, mimeType));
                    saveBytesAsync(data, name, mime);
                }
                return;
            }
            nudgeNotificationPermission();
            PendingDownload download = new PendingDownload();
            download.url = url;
            download.userAgent = userAgent;
            download.contentDisposition = contentDisposition;
            download.mimeType = mimeType;
            download.fileName = URLUtil.guessFileName(url, contentDisposition, mimeType);
            if (needsLegacyWritePermission()) {
                pendingDownload = download;
                requestPermissions(new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, REQ_WRITE_STORAGE);
                return;
            }
            enqueueDownload(download);
        }
    }

    private void enqueueDownload(PendingDownload download) {
        if (download == null || download.url == null || download.url.trim().isEmpty()) return;
        try {
            DownloadManager manager = (DownloadManager) getSystemService(DOWNLOAD_SERVICE);
            if (manager == null) return;
            DownloadManager.Request request = new DownloadManager.Request(Uri.parse(download.url));
            request.setTitle(download.fileName);
            request.setDescription(download.url);
            request.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
            request.setMimeType(download.mimeType);
            request.setAllowedOverMetered(true);
            request.setAllowedOverRoaming(true);
            String cookies = CookieManager.getInstance().getCookie(download.url);
            if (cookies != null && !cookies.isEmpty()) {
                request.addRequestHeader("Cookie", cookies);
            }
            if (download.userAgent != null && !download.userAgent.isEmpty()) {
                request.addRequestHeader("User-Agent", download.userAgent);
            }
            request.setDestinationInExternalPublicDir(
                Environment.DIRECTORY_DOWNLOADS,
                buildDownloadRelativePath(download.fileName)
            );
            manager.enqueue(request);
        } catch (Throwable e) {
            Log.w("WebToApp", "enqueueDownload failed: " + download.url, e);
        }
    }

    private String buildDownloadRelativePath(String fileName) {
        return sanitizeFileSegment(fileName);
    }

    private String sanitizeFileSegment(String value) {
        String cleaned = String.valueOf(value == null ? "" : value).replaceAll("[\\\\/:*?\"<>|]+", "_").trim();
        return cleaned.isEmpty() ? "download.bin" : cleaned;
    }

    // ── In-page file export bridge (issue #37) ──────────────────────────
    // Pages call window.WebToApp.saveFile(dataUrl, fileName, mimeType) to
    // save generated content (CSV / PDF / …) into the public Downloads
    // folder, which file managers and the system Downloads app can browse.
    // There is intentionally NO window.android.* alias: that name belongs to
    // other packers' bridges with unknown signatures, and guessing them
    // would silently do the wrong thing. Documented contract:
    //   dataUrl  "data:[<mime>][;base64],<payload>" or a raw base64 payload
    //   fileName plain file name; path separators are stripped server-side
    //   mimeType e.g. "text/csv"; empty falls back to octet-stream
    private final class WebAppBridge {
        // Centre of the injected fullscreen button in WebView pixel coords.
        float fullscreenX = -1f;
        float fullscreenY = -1f;
        // Whether the current page focus is on the injected fullscreen button.
        // OK must send a trusted touch there for requestFullscreen(); any other
        // focused element must be activated through __wtaTvActivate() instead.
        boolean focusIsFsBtn = true;

        @JavascriptInterface public void setFullscreenButtonRect(float x, float y) {
            fullscreenX = x;
            fullscreenY = y;
        }

        @JavascriptInterface public void setFocusIsFsBtn(boolean value) {
            focusIsFsBtn = value;
        }

        // Called by the injected back script only when no in-page modal was
        // found. Carries the real SPA URL (more reliable than WebView.getUrl()).
        @JavascriptInterface public void performBack(final String currentUrl) {
            if (webView == null) return;
            webView.post(new Runnable() {
                @Override public void run() { performBrowserBack(currentUrl); }
            });
        }

        @JavascriptInterface public void logBack(String info) {
            Log.d("WebToAppTV", "BACK " + info);
        }

        @JavascriptInterface public void saveFile(String dataUrl, String fileName, String mimeType) {
            final byte[] data = decodeDataUrl(dataUrl);
            final String safeName = sanitizeFileSegment(fileName);
            final String mime = mimeType != null ? mimeType : "";
            if (data == null) {
                toastOnUi("保存失败：文件内容无效");
                Log.w("WebToApp", "saveFile: undecodable payload");
                return;
            }
            if (needsBridgeStoragePermission()) {
                runOnUiThread(new Runnable() {
                    @Override public void run() {
                        try {
                            requestPermissions(
                                new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},
                                REQ_BRIDGE_STORAGE);
                        } catch (Throwable ignored) {}
                    }
                });
                toastOnUi("需要存储权限，授权后请重新导出");
                return;
            }
            saveBytesAsync(data, safeName, mime);
        }
        @JavascriptInterface public void onExportFailed(String message) {
            Log.w("WebToApp", "page-side export failed: " + message);
            toastOnUi("导出失败，请重试");
        }
    }

    private boolean needsBridgeStoragePermission() {
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.Q
            && checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED;
    }

    // Only the page itself can read its own blob: URLs, so resolve them with
    // page-side fetch() and hand the base64 back to the bridge. The script is
    // built without a single double-quote so neither the Java nor the Python
    // template layer needs escaping.
    private static final String BLOB_FETCH_PREFIX =
        "(function(u,n,m){"
        + "fetch(u).then(function(r){return r.blob();}).then(function(b){"
        + "var f=new FileReader();"
        + "f.onload=function(){try{WebToApp.saveFile(f.result,n,m);}catch(e){WebToApp.onExportFailed(String(e));}};"
        + "f.onerror=function(){WebToApp.onExportFailed('read failed');};"
        + "f.readAsDataURL(b);"
        + "}).catch(function(e){WebToApp.onExportFailed(String(e));});"
        + "})('";
    private static final String BLOB_FETCH_SEP = "','";
    private static final String BLOB_FETCH_SUFFIX = "');";

    private void resolveBlobDownload(final String blobUrl, final String fileName, final String mimeType) {
        runOnUiThread(new Runnable() {
            @Override public void run() {
                try {
                    if (webView == null) return;
                    String script = BLOB_FETCH_PREFIX + jsSingleQuote(blobUrl)
                        + BLOB_FETCH_SEP + jsSingleQuote(fileName)
                        + BLOB_FETCH_SEP + jsSingleQuote(mimeType) + BLOB_FETCH_SUFFIX;
                    webView.evaluateJavascript(script, null);
                } catch (Throwable e) {
                    Log.w("WebToApp", "blob resolve failed", e);
                    toastOnUi("导出失败，请重试");
                }
            }
        });
    }

    private static String jsSingleQuote(String value) {
        String s = String.valueOf(value == null ? "" : value);
        return s.replace("\\", "\\\\").replace("'", "\\'");
    }

    private static byte[] decodeDataUrl(String dataUrl) {
        if (dataUrl == null) return null;
        String text = dataUrl.trim();
        if (text.isEmpty()) return null;
        try {
            int comma = text.indexOf(',');
            if (comma < 0) {
                return Base64.decode(text, Base64.DEFAULT);
            }
            String header = text.substring(0, comma);
            String payload = text.substring(comma + 1);
            if (header.contains(";base64")) {
                return Base64.decode(payload, Base64.DEFAULT);
            }
            return java.net.URLDecoder.decode(payload, "UTF-8").getBytes("UTF-8");
        } catch (Throwable e) {
            Log.w("WebToApp", "decodeDataUrl failed", e);
            return null;
        }
    }

    private void saveBytesAsync(final byte[] data, final String fileName, final String mime) {
        new Thread(new Runnable() {
            @Override public void run() {
                boolean ok = writeDownloadFile(data, fileName, mime);
                toastOnUi(ok ? "已保存到下载目录：" + fileName : "保存失败，请重试");
            }
        }).start();
    }

    private boolean writeDownloadFile(byte[] data, String fileName, String mimeType) {
        if (data == null || data.length == 0) return false;
        String mime = mimeType != null && !mimeType.isEmpty()
            ? mimeType : "application/octet-stream";
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                // Scoped storage: MediaStore lands the file in the public
                // Downloads collection — no permission needed, and it shows
                // up in file managers (this is what issue #37 was missing).
                ContentValues values = new ContentValues();
                values.put(MediaStore.Downloads.DISPLAY_NAME, fileName);
                values.put(MediaStore.Downloads.MIME_TYPE, mime);
                values.put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS);
                ContentResolver resolver = getContentResolver();
                Uri uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values);
                if (uri == null) return false;
                OutputStream out = resolver.openOutputStream(uri);
                if (out == null) return false;
                out.write(data);
                out.close();
                return true;
            }
            if (checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    != PackageManager.PERMISSION_GRANTED) {
                return false;
            }
            java.io.File dir = Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOWNLOADS);
            if (!dir.exists() && !dir.mkdirs()) return false;
            java.io.File target = new java.io.File(dir, fileName);
            java.io.FileOutputStream out = new java.io.FileOutputStream(target);
            out.write(data);
            out.close();
            sendBroadcast(new Intent(
                Intent.ACTION_MEDIA_SCANNER_SCAN_FILE, Uri.fromFile(target)));
            return true;
        } catch (Throwable e) {
            Log.w("WebToApp", "writeDownloadFile failed", e);
            return false;
        }
    }

    private void toastOnUi(final String message) {
        runOnUiThread(new Runnable() {
            @Override public void run() {
                try {
                    Toast.makeText(M.this, message, Toast.LENGTH_LONG).show();
                } catch (Throwable ignored) {}
            }
        });
    }

    // Android 13+ gates the DownloadManager "download complete" notification
    // behind POST_NOTIFICATIONS. Nudge once per download; the download itself
    // never waits for the grant.
    private void nudgeNotificationPermission() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                    && checkSelfPermission("android.permission.POST_NOTIFICATIONS")
                        != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(
                    new String[]{"android.permission.POST_NOTIFICATIONS"}, REQ_NOTIFY);
            }
        } catch (Throwable ignored) {}
    }

    private boolean needsLegacyWritePermission() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
            && Build.VERSION.SDK_INT < Build.VERSION_CODES.Q
            && checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED;
    }

    private void handleGeolocationPermission(String origin, GeolocationPermissions.Callback callback) {
        if (hasAnyPermission(Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION)) {
            callback.invoke(origin, true, false);
            return;
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            callback.invoke(origin, true, false);
            return;
        }
        pendingGeolocationOrigin = origin;
        pendingGeolocationCallback = callback;
        requestPermissions(
            new String[]{Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.ACCESS_COARSE_LOCATION},
            REQ_LOCATION
        );
    }

    private void handleMediaPermission(PermissionRequest request) {
        if (request == null) return;
        ArrayList<String> missingPermissions = new ArrayList<String>();
        for (String resource : request.getResources()) {
            if (PermissionRequest.RESOURCE_VIDEO_CAPTURE.equals(resource) && !hasPermission(Manifest.permission.CAMERA)) {
                missingPermissions.add(Manifest.permission.CAMERA);
            }
            if (PermissionRequest.RESOURCE_AUDIO_CAPTURE.equals(resource) && !hasPermission(Manifest.permission.RECORD_AUDIO)) {
                missingPermissions.add(Manifest.permission.RECORD_AUDIO);
            }
        }
        if (missingPermissions.isEmpty() || Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            request.grant(request.getResources());
            return;
        }
        pendingPermissionRequest = request;
        requestPermissions(missingPermissions.toArray(new String[0]), REQ_MEDIA);
    }

    private boolean hasPermission(String permission) {
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.M
            || checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED;
    }

    private boolean hasAnyPermission(String first, String second) {
        return hasPermission(first) || hasPermission(second);
    }

    private boolean allGranted(int[] grantResults) {
        if (grantResults == null || grantResults.length == 0) return false;
        for (int result : grantResults) {
            if (result != PackageManager.PERMISSION_GRANTED) return false;
        }
        return true;
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_FILE_CHOOSER) return;
        ValueCallback<Uri[]> callback = pendingFileChoiceCallback;
        pendingFileChoiceCallback = null;
        if (callback == null) return;  // activity recreated meanwhile: WebView's callback is gone
        // Deliver even when the user cancelled (null result) — leaving the
        // callback hanging makes WebView ignore all later file-input taps.
        callback.onReceiveValue(parseFileChooserResult(resultCode, data));
    }

    /**
     * Converts the system picker result into the Uri[] the WebView expects.
     * FileChooserParams.parseResult() only handles single selection, so
     * multi-select results are read from ClipData here.
     */
    private Uri[] parseFileChooserResult(int resultCode, Intent data) {
        if (resultCode != RESULT_OK || data == null) return null;
        ClipData clip = data.getClipData();
        if (clip != null) {
            ArrayList<Uri> uris = new ArrayList<Uri>();
            for (int i = 0; i < clip.getItemCount(); i++) {
                Uri uri = clip.getItemAt(i).getUri();
                if (uri != null) uris.add(uri);
            }
            return uris.isEmpty() ? null : uris.toArray(new Uri[0]);
        }
        Uri single = data.getData();
        return single != null ? new Uri[]{single} : null;
    }

    @Override public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQ_WRITE_STORAGE) {
            PendingDownload download = pendingDownload;
            pendingDownload = null;
            if (allGranted(grantResults)) {
                enqueueDownload(download);
            }
            return;
        }
        if (requestCode == REQ_BRIDGE_STORAGE) {
            // Bridge saves hold no pending bytes by design (a retry just
            // re-invokes saveFile), so only acknowledge the grant result.
            toastOnUi(allGranted(grantResults) ? "已获得权限，请重新导出" : "缺少存储权限，无法保存");
            return;
        }
        if (requestCode == REQ_LOCATION) {
            GeolocationPermissions.Callback callback = pendingGeolocationCallback;
            String origin = pendingGeolocationOrigin;
            pendingGeolocationCallback = null;
            pendingGeolocationOrigin = null;
            if (callback != null) {
                callback.invoke(origin, allGranted(grantResults), false);
            }
            return;
        }
        if (requestCode == REQ_MEDIA) {
            PermissionRequest request = pendingPermissionRequest;
            pendingPermissionRequest = null;
            if (request != null) {
                if (allGranted(grantResults)) request.grant(request.getResources());
                else request.deny();
            }
        }
    }

    /**
     * TV remote: consume DPAD/ENTER/media keys in TV mode and drive the
     * injected page helpers. Returning true keeps WebView from also handling
     * the same key, which would move focus twice or click twice.
     */
    @Override public boolean dispatchKeyEvent(KeyEvent event) {
        // Emergency exit: a held BACK must always work. In TV mode BACK is
        // consumed by the page and by fullscreen handling, so a login popup
        // that refuses to close would otherwise trap the user with no way to
        // close it, go back, or quit the app.
        if (event.getKeyCode() == KeyEvent.KEYCODE_BACK
                && event.getAction() == KeyEvent.ACTION_DOWN
                && event.getRepeatCount() >= 12) {
            exitApp();
            return true;
        }
        // In native WebView fullscreen the WebView is detached, so page JS can
        // no longer see these keys. Route them to the native player instead.
        if (customView != null) {
            return handleFullscreenKey(event);
        }
        // TV mode owns BACK: dismiss a modal, else do a browser back. Consuming
        // both DOWN and UP here prevents the system from ever finishing the app
        // while the user is on a sub-page.
        if (config != null && config.tvMode
                && event.getKeyCode() == KeyEvent.KEYCODE_BACK) {
            if (event.getAction() == KeyEvent.ACTION_DOWN && webView != null) {
                webView.evaluateJavascript(
                    "typeof __wtaTvBack==='function'&&__wtaTvBack()", null);
            }
            return true;
        }
        if (config != null && config.tvMode && config.tvRemote && webView != null) {
            int action = event.getAction();
            int keyCode = event.getKeyCode();
            if (action == KeyEvent.ACTION_DOWN || action == KeyEvent.ACTION_UP) {
                if (isDpadKey(keyCode)) {
                    if (action == KeyEvent.ACTION_DOWN) {
                        int dx = 0;
                        int dy = 0;
                        if (keyCode == KeyEvent.KEYCODE_DPAD_LEFT) dx = -1;
                        else if (keyCode == KeyEvent.KEYCODE_DPAD_RIGHT) dx = 1;
                        else if (keyCode == KeyEvent.KEYCODE_DPAD_UP) dy = -1;
                        else if (keyCode == KeyEvent.KEYCODE_DPAD_DOWN) dy = 1;
                        webView.evaluateJavascript(
                            "typeof __wtaTvMoveFocus==='function'&&__wtaTvMoveFocus(" + dx + "," + dy + ")",
                            null);
                    }
                    return true;
                }
                if (keyCode == KeyEvent.KEYCODE_ENTER
                        || keyCode == KeyEvent.KEYCODE_DPAD_CENTER
                        || keyCode == KeyEvent.KEYCODE_NUMPAD_ENTER) {
                    // Focus on the injected fullscreen button: only a trusted
                    // touch can grant requestFullscreen(), so synthesize one
                    // there. Every OTHER focused element (movie card, link,
                    // player control) is activated through its own click
                    // handler via __wtaTvActivate() — touching the fullscreen
                    // button unconditionally made cards look unresponsive.
                    if (action == KeyEvent.ACTION_DOWN && webBridge != null) {
                        Log.d("WebToAppTV", "OK focusIsFsBtn=" + webBridge.focusIsFsBtn
                                + " fsX=" + webBridge.fullscreenX + " fsY=" + webBridge.fullscreenY);
                        if (webBridge.focusIsFsBtn
                                && webBridge.fullscreenX >= 0f && webBridge.fullscreenY >= 0f) {
                            long t = SystemClock.uptimeMillis();
                            MotionEvent down = MotionEvent.obtain(
                                t, t, MotionEvent.ACTION_DOWN,
                                webBridge.fullscreenX, webBridge.fullscreenY, 0);
                            webView.dispatchTouchEvent(down);
                            MotionEvent up = MotionEvent.obtain(
                                t, t, MotionEvent.ACTION_UP,
                                webBridge.fullscreenX, webBridge.fullscreenY, 0);
                            webView.dispatchTouchEvent(up);
                        } else {
                            webView.evaluateJavascript(
                                "typeof __wtaTvActivate==='function'&&__wtaTvActivate()", null);
                        }
                    }
                    return true;
                }
                String mediaAction = tvMediaAction(keyCode);
                if (mediaAction != null) {
                    if (action == KeyEvent.ACTION_DOWN) {
                        webView.evaluateJavascript(
                            "typeof __wtaTvMedia==='function'&&__wtaTvMedia('" + mediaAction + "')",
                            null);
                    }
                    return true;
                }
            }
        }
        // Captions key works even when DPAD navigation is turned off. It
        // opens/closes the on-screen track picker injected above.
        if (config != null && config.tvMode && config.tvSubtitles
                && webView != null && event.getKeyCode() == KeyEvent.KEYCODE_CAPTIONS) {
            int action = event.getAction();
            if (action == KeyEvent.ACTION_DOWN) {
                webView.evaluateJavascript(
                    "typeof __wtaTvSubtitles==='function'&&__wtaTvSubtitles()", null);
            }
            return true;
        }
        return super.dispatchKeyEvent(event);
    }

    private static boolean isDpadKey(int keyCode) {
        return keyCode == KeyEvent.KEYCODE_DPAD_UP
            || keyCode == KeyEvent.KEYCODE_DPAD_DOWN
            || keyCode == KeyEvent.KEYCODE_DPAD_LEFT
            || keyCode == KeyEvent.KEYCODE_DPAD_RIGHT;
    }

    private static android.widget.VideoView findVideoView(View v) {
        if (v instanceof android.widget.VideoView) return (android.widget.VideoView) v;
        if (v instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) v;
            for (int i = 0; i < group.getChildCount(); i++) {
                android.widget.VideoView found = findVideoView(group.getChildAt(i));
                if (found != null) return found;
            }
        }
        return null;
    }

    private void runFullscreenJsMedia(String action) {
        if (webView == null) return;
        if ("captions".equals(action)) {
            webView.evaluateJavascript(
                "typeof __wtaTvSubtitles==='function'&&__wtaTvSubtitles()", null);
            return;
        }
        webView.evaluateJavascript(
            "typeof __wtaTvMedia==='function'&&__wtaTvMedia('" + action + "')", null);
    }

    private boolean dispatchFullscreenKey(KeyEvent event) {
        if (customView == null) return false;
        if (customView.dispatchKeyEvent(event)) return true;
        View focused = customView.findFocus();
        if (focused != null && focused != customView && focused.dispatchKeyEvent(event)) {
            return true;
        }
        android.widget.VideoView vv = findVideoView(customView);
        return vv != null && vv.dispatchKeyEvent(event);
    }

    private boolean handleFullscreenKey(KeyEvent event) {
        int action = event.getAction();
        int keyCode = event.getKeyCode();
        if (action != KeyEvent.ACTION_DOWN && action != KeyEvent.ACTION_UP) {
            return super.dispatchKeyEvent(event);
        }
        if (keyCode == KeyEvent.KEYCODE_BACK) {
            if (action == KeyEvent.ACTION_DOWN && webView != null) {
                webView.getWebChromeClient().onHideCustomView();
            }
            return true;
        }
        if (keyCode == KeyEvent.KEYCODE_DPAD_UP) {
            if (action == KeyEvent.ACTION_DOWN && fullscreenExitButton != null) {
                fullscreenExitButton.requestFocus();
            }
            return true;
        }
        if (keyCode == KeyEvent.KEYCODE_DPAD_DOWN) {
            if (action == KeyEvent.ACTION_DOWN) customView.requestFocus();
            return true;
        }
        if (keyCode == KeyEvent.KEYCODE_ENTER
                || keyCode == KeyEvent.KEYCODE_DPAD_CENTER
                || keyCode == KeyEvent.KEYCODE_NUMPAD_ENTER) {
            if (action == KeyEvent.ACTION_DOWN) {
                if (fullscreenExitButton != null && fullscreenExitButton.hasFocus()) {
                    fullscreenExitButton.performClick();
                } else {
                    // Native media controls rarely take focus from a remote,
                    // so make OK a reliable play/pause toggle as well.
                    runFullscreenJsMedia("toggle");
                    dispatchFullscreenKey(event);
                }
            }
            return true;
        }
        if (keyCode == KeyEvent.KEYCODE_DPAD_LEFT || keyCode == KeyEvent.KEYCODE_DPAD_RIGHT) {
            if (action == KeyEvent.ACTION_DOWN) {
                // The Chromium custom view often ignores KeyEvents, but the
                // WebView JS engine keeps running while detached, so drive the
                // same <video> element there and try native as a fallback.
                String seek = keyCode == KeyEvent.KEYCODE_DPAD_LEFT ? "rw" : "ff";
                runFullscreenJsMedia(seek);
                int seekCode = keyCode == KeyEvent.KEYCODE_DPAD_LEFT
                    ? KeyEvent.KEYCODE_MEDIA_REWIND
                    : KeyEvent.KEYCODE_MEDIA_FAST_FORWARD;
                long t = SystemClock.uptimeMillis();
                dispatchFullscreenKey(new KeyEvent(t, t, KeyEvent.ACTION_DOWN, seekCode, 0));
                dispatchFullscreenKey(new KeyEvent(t, t, KeyEvent.ACTION_UP, seekCode, 0));
            }
            return true;
        }
        if (keyCode == KeyEvent.KEYCODE_CAPTIONS) {
            if (action == KeyEvent.ACTION_DOWN) {
                if (!dispatchFullscreenKey(event)) runFullscreenJsMedia("captions");
            }
            return true;
        }
        String media = tvMediaAction(keyCode);
        if (media != null) {
            if (action == KeyEvent.ACTION_DOWN) {
                runFullscreenJsMedia(media);
                dispatchFullscreenKey(event);
            }
            return true;
        }
        if (dispatchFullscreenKey(event)) return true;
        return super.dispatchKeyEvent(event);
    }

    private static String tvMediaAction(int keyCode) {
        switch (keyCode) {
            case KeyEvent.KEYCODE_MEDIA_PLAY_PAUSE:
                return "toggle";
            case KeyEvent.KEYCODE_MEDIA_PLAY:
                return "play";
            case KeyEvent.KEYCODE_MEDIA_PAUSE:
                return "pause";
            case KeyEvent.KEYCODE_MEDIA_FAST_FORWARD:
            case KeyEvent.KEYCODE_MEDIA_SKIP_FORWARD:
                return "ff";
            case KeyEvent.KEYCODE_MEDIA_REWIND:
            case KeyEvent.KEYCODE_MEDIA_SKIP_BACKWARD:
                return "rw";
            case KeyEvent.KEYCODE_MEDIA_NEXT:
                return "next";
            case KeyEvent.KEYCODE_MEDIA_PREVIOUS:
                return "prev";
            case KeyEvent.KEYCODE_MEDIA_STOP:
                return "stop";
            default:
                return null;
        }
    }

    @Override public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (hasFocus) applyImmersiveMode();
    }

    /** True when the current page is the site's landing page (root path). */
    private boolean isHomePage(String url) {
        if (url == null || url.isEmpty()) return true;
        try {
            String path = Uri.parse(url).getPath();
            if (path == null || path.isEmpty() || path.equals("/")) return true;
            if (homeUrl != null) {
                String homePath = Uri.parse(homeUrl).getPath();
                if (homePath != null && homePath.equals(path)) return true;
            }
        } catch (Throwable ignored) {}
        return false;
    }

    /**
     * BACK on a sub-page must never finish the app. Prefer the browser history;
     * when the stack is empty (deep link / SPA), fall back to the launch URL.
     * Only the actual home page is allowed to close the activity.
     */
    private void performBrowserBack(String currentUrl) {
        if (webView == null) return;
        if (customView != null) {
            webView.getWebChromeClient().onHideCustomView();
            return;
        }
        if (!isHomePage(currentUrl)) {
            if (webView.canGoBack()) webView.goBack();
            else if (config != null && config.url != null) webView.loadUrl(config.url);
            return;
        }
        super.onBackPressed();
    }

    @Override public void onBackPressed() {
        if (customView != null && webView != null) {
            webView.getWebChromeClient().onHideCustomView();
            return;
        }
        performBrowserBack(webView != null ? webView.getUrl() : null);
    }

    /**
     * Leave the app no matter what state the page is in. Used only by the
     * held-BACK escape hatch: the TV navigation guard deliberately swallows
     * BACK so a page can never kill the app by accident, which also means a
     * site popup can otherwise keep the user captive forever.
     */
    private void exitApp() {
        try {
            finishAffinity();
        } catch (Throwable ignored) {
            finish();
        }
    }

    @Override protected void onDestroy() {
        pendingDownload = null;
        pendingGeolocationCallback = null;
        pendingGeolocationOrigin = null;
        pendingPermissionRequest = null;
        pendingFileChoiceCallback = null;
        if (webView != null) {
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }

    private static final class PendingDownload {
        String url;
        String userAgent;
        String contentDisposition;
        String mimeType;
        String fileName;
    }

    private static final class AppConfig {
        String url = "about:blank";
        boolean immersiveFullscreen = false;
        boolean desktopMode = false;
        // Extra ad hosts injected at build time via webtoapp_config.json.
        // Allows blocking site-specific ad domains without rebuilding the APK template.
        Set<String> extraAdHosts = new HashSet<>();
        // TV profile: keep playback/navigation inside the app and restrict
        // http(s) navigation to the launch host plus tvNavHosts.
        boolean tvMode = false;
        boolean tvAutoFullscreen = false;
        boolean tvRemote = false;
        boolean tvSubtitles = false;
        Set<String> tvNavHosts = new HashSet<>();
        String startHost = null;
    }
}
"""

MANIFEST_XML = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{pkg}" android:versionCode="{version_code}" android:versionName="{version_name}">
    <uses-sdk android:minSdkVersion="21" android:targetSdkVersion="36"/>
    <uses-feature android:name="android.software.leanback" android:required="false"/>
    <uses-feature android:name="android.hardware.touchscreen" android:required="false"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <uses-permission android:name="android.permission.RECORD_AUDIO"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" android:maxSdkVersion="28"/>
    <uses-permission android:name="android.permission.POST_NOTIFICATIONS"/>
    <application android:label="{name}" android:icon="@mipmap/ic_launcher"
        android:usesCleartextTraffic="true">
        <activity android:name="w.M" android:exported="true"
            android:theme="@android:style/Theme.NoTitleBar"
            android:configChanges="orientation|screenSize|screenLayout|keyboardHidden|uiMode|navigation">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LEANBACK_LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
"""


class ApkBuilder:
    TEMPLATE_PACKAGE = "com.webtoapp.template"
    TEMPLATE_APP_NAME = "WebToApp Template"
    TEMPLATE_VERSION_CODE = 1
    TEMPLATE_VERSION_NAME = "1.0"
    # Human-readable prefix; the effective revision appends a content hash
    # (see _template_revision) so editing ACTIVITY_JAVA/MANIFEST_XML can never
    # silently serve a stale cached template — the old hand-bumped constant
    # relied on developers remembering to change it (AGENTS.md even documented
    # a manual cache-delete workaround for exactly that failure mode).
    TEMPLATE_REVISION = "2026-11-27-tv-escape-4"

    @classmethod
    def _template_revision(cls) -> str:
        digest = hashlib.sha256(
            (ACTIVITY_JAVA + "\n" + MANIFEST_XML).encode("utf-8")
        ).hexdigest()[:12]
        return f"{cls.TEMPLATE_REVISION}-{digest}"
    # Keystore used only to sign the throwaway base *template* APK. The template
    # is always re-signed per-app afterwards, so this key never reaches users.
    TEMPLATE_KEY_ALIAS = "webtoapp"
    TEMPLATE_APK_NAME = "android-template.apk"

    def __init__(self):
        self.sdk = self._find_sdk()
        self.root = Path(__file__).resolve().parents[2]
        self.certs_dir = self.root / "certs"
        self.template_dir = self.root / "server" / "engine" / "_android_template"
        self.android_tools_dir = self.root / "server" / "engine" / "_android_tools"
        # Per-app signing keystores live here, one keystore per app_id. Kept
        # private (never publicly served) and out of version control.
        self.app_keys_dir = Path(config.android_keystore_dir())
        self.template_dir.mkdir(parents=True, exist_ok=True)
        self.android_tools_dir.mkdir(parents=True, exist_ok=True)
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        self.app_keys_dir.mkdir(parents=True, exist_ok=True)

    def _find_sdk(self):
        for p in [
            os.environ.get("ANDROID_HOME"),
            os.environ.get("ANDROID_SDK_ROOT"),
            os.path.expanduser("~/Library/Android/sdk"),
            os.path.expanduser("~/Android/Sdk"),
        ]:
            if p and os.path.isdir(p):
                return p
        return None

    def _find_tool(self, name):
        tools = self._find_tools(name)
        return tools[0] if tools else None

    def _find_tools(self, name):
        results = []
        # Windows SDK tools carry .exe/.bat suffixes; checking only the bare
        # name made local Windows builds silently fall back to the PWA shell.
        names = [name]
        if os.name == "nt":
            names.extend([name + ".exe", name + ".bat"])
        if self.sdk:
            bt = Path(self.sdk) / "build-tools"
            if bt.exists():
                for v in sorted(bt.iterdir(), reverse=True):
                    for candidate in names:
                        f = v / candidate
                        if f.exists():
                            results.append(str(f))
                            break
        path_tool = shutil.which(name)
        if path_tool and path_tool not in results:
            results.append(path_tool)
        return results

    def _find_jar(self):
        if not self.sdk:
            return None
        p = Path(self.sdk) / "platforms"
        if p.exists():
            for v in sorted(p.iterdir(), reverse=True):
                j = v / "android.jar"
                if j.exists():
                    return str(j)
        return None

    @property
    def can_build_apk(self):
        return self._can_patch_apk() and (self._template_apk_path().exists() or self._can_build_template())

    def _can_patch_apk(self):
        # The forkless patcher needs no apktool — just openssl (via
        # _export_signing_material) and our own v1/v2 signer. keytool/java are
        # only required to *mint* keystores; an existing per-app keystore is
        # used as-is. They stay in the list so hosts without a JDK don't get
        # silently switched to the PWA fallback on first build.
        return all([
            shutil.which("openssl"),
            shutil.which("keytool"),
            shutil.which("java"),
        ])

    def _can_build_template(self):
        return all([
            self.sdk,
            self._find_tool("aapt2"),
            self._find_tool("d8"),
            shutil.which("javac"),
            self._find_jar(),
            self._find_tool("apksigner"),
        ])

    def build_apk(self, output, url, name, pkg, icon_png=None, version_code=1, version_name="1.0", feature_options=None, app_id=None):
        if not self.can_build_apk:
            return False
        try:
            template_apk = self._ensure_template_apk(icon_png)
            if not template_apk or not template_apk.exists():
                return False
            self._patch_template_apk(
                template_apk=template_apk,
                output=Path(output),
                url=url,
                name=name,
                pkg=pkg,
                icon_png=icon_png,
                version_code=version_code,
                version_name=version_name,
                feature_options=feature_options or {},
                app_id=app_id or pkg,
            )
            if not self._validate_built_apk(Path(output)):
                raise RuntimeError("built APK failed alignment validation")
            return True
        except Exception as e:
            log_event("apk_build_failed", error=str(e))
            return False

    def _ensure_template_apk(self, icon_png=None):
        template_apk = self._template_apk_path()
        revision_file = self.template_dir / "template.revision"
        revision = self._template_revision()
        current_revision = revision_file.read_text().strip() if revision_file.exists() else ""
        if template_apk.exists() and current_revision == revision:
            return template_apk
        if template_apk.exists():
            template_apk.unlink()
        built = self._build_base_template(template_apk, icon_png)
        if built and built.exists():
            revision_file.write_text(revision)
        return built if built and built.exists() else None

    def _template_apk_path(self):
        return self.template_dir / self.TEMPLATE_APK_NAME

    def _build_base_template(self, template_apk: Path, icon_png=None):
        aapt2_candidates = self._find_tools("aapt2")
        d8 = self._find_tool("d8")
        javac = shutil.which("javac")
        jar = self._find_jar()
        apksigner = self._find_tool("apksigner")
        if not all([aapt2_candidates, d8, javac, jar, apksigner]):
            return None

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            src = tmp / "src" / "w"
            src.mkdir(parents=True)
            (src / "M.java").write_text(ACTIVITY_JAVA, encoding="utf-8")

            manifest = tmp / "AndroidManifest.xml"
            manifest.write_text(
                MANIFEST_XML.format(
                    pkg=self.TEMPLATE_PACKAGE,
                    name=self.TEMPLATE_APP_NAME,
                    version_code=self.TEMPLATE_VERSION_CODE,
                    version_name=self.TEMPLATE_VERSION_NAME,
                ),
                encoding="utf-8",
            )

            mipmap = tmp / "res" / "mipmap"
            mipmap.mkdir(parents=True)
            if icon_png:
                (mipmap / "ic_launcher.png").write_bytes(icon_png)
            else:
                (mipmap / "ic_launcher.png").write_bytes(self._blank_png())

            compiled = tmp / "compiled"
            compiled.mkdir()
            apk_unsigned = tmp / "app-unsigned.apk"
            aapt2 = self._run_aapt2_with_fallback(aapt2_candidates, compiled, tmp, manifest, jar, apk_unsigned)
            if not aapt2:
                print("[ApkBuilder] All aapt2 versions failed")
                return None

            classes = tmp / "classes"
            classes.mkdir()
            _run_tool(
                # -proc:none skips the annotation-processor classpath scan,
                # which is pure startup overhead for a processor-less build.
                [javac, "-proc:none", "-encoding", "UTF-8", "-source", "1.8", "-target", "1.8", "-bootclasspath", jar, "-d", str(classes), str(src / "M.java")],
                check=True,
                capture_output=True,
            )

            dex_out = tmp / "dex"
            dex_out.mkdir()
            class_files = [str(f) for f in classes.rglob("*.class")]
            _run_tool([d8, "--output", str(dex_out)] + class_files, check=True, capture_output=True)

            with zipfile.ZipFile(apk_unsigned, "a") as z:
                z.write(dex_out / "classes.dex", "classes.dex")
                z.writestr("assets/webtoapp_config.json", self._config_json("https://example.com", {}))

            aligned = tmp / "app-aligned.apk"
            self._align_apk(apk_unsigned, aligned)

            signed = tmp / "app-signed.apk"
            shutil.copy(aligned, signed)
            keystore, password, alias = self._ensure_template_keystore()
            _run_tool(
                [
                    apksigner,
                    "sign",
                    "--ks",
                    str(keystore),
                    "--ks-pass",
                    f"pass:{password}",
                    "--key-pass",
                    f"pass:{password}",
                    "--ks-key-alias",
                    alias,
                    str(signed),
                ],
                check=True,
                capture_output=True,
            )
            shutil.copy(signed, template_apk)
            return template_apk

    def _ensure_template_keystore(self):
        """Keystore for signing the throwaway base template APK.

        Not security-critical (the template is re-signed per-app), but the
        password is sourced from config rather than hard-coded. Returns
        ``(keystore_path, password, alias)``.
        """
        keystore = self.certs_dir / "android-template.keystore"
        password = config.android_template_keystore_password()
        alias = self.TEMPLATE_KEY_ALIAS
        if keystore.exists():
            return keystore, password, alias
        self._generate_keystore(
            keystore=keystore,
            password=password,
            alias=alias,
            dname="CN=WebToApp Build Template,O=WebToApp,C=CN",
        )
        return keystore, password, alias

    def _ensure_app_keystore(self, app_id: str):
        """Return ``(keystore_path, password, alias)`` for ``app_id``.

        Generated once on first build and reused on every later build of the
        same app_id, so the signing certificate stays stable — required for
        Android to accept reinstalls as in-place updates (same package name +
        same signer). Each app_id gets a distinct random key, so no two
        generated apps share a signing certificate.

        The key *alias* is also randomized per app. apksigner derives the v1
        (JAR) signature filenames from the alias (e.g. alias ``Ab3xK`` →
        ``META-INF/AB3XK.SF`` / ``.RSA``), so a fixed alias would make every
        generated APK share the same ``APP.SF``/``APP.RSA`` names — a uniform
        pattern AV engines can fingerprint in bulk. A random alias gives each
        app distinct META-INF filenames. The alias is persisted so rebuilds of
        the same app_id keep stable filenames (filename changes don't affect
        update-eligibility, which is keyed on the certificate, but keeping them
        stable avoids churn).
        """
        safe_id = re.sub(r"[^a-z0-9_]", "", str(app_id or "").lower()) or "app"
        keystore = self.app_keys_dir / f"{safe_id}.keystore"
        meta_path = self.app_keys_dir / f"{safe_id}.json"
        if keystore.exists() and meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text())
                password = str(meta.get("password") or "")
                stored_alias = str(meta.get("alias") or "")
                if password and stored_alias:
                    return keystore, password, stored_alias
            except Exception:
                pass  # corrupt metadata: fall through and regenerate
        # First build for this app_id (or metadata lost): mint a fresh key.
        if keystore.exists():
            keystore.unlink()
        password = secrets.token_urlsafe(24)
        alias = self._random_key_alias()
        self._generate_keystore(
            keystore=keystore,
            password=password,
            alias=alias,
            dname=self._random_cert_dname(),
        )
        meta_path.write_text(json.dumps({"alias": alias, "password": password}, ensure_ascii=False))
        for path in (meta_path, keystore):
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        return keystore, password, alias

    @staticmethod
    def _random_key_alias() -> str:
        """A random, alpha-led alias (letters/digits). apksigner uppercases it
        for the v1 META-INF/<ALIAS>.SF/.RSA filenames, so this randomizes those
        names per app while staying a valid keystore alias."""
        first = secrets.choice("abcdefghijklmnopqrstuvwxyz")
        rest = "".join(
            secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789")
            for _ in range(secrets.randbelow(5) + 7)  # total length 8..12
        )
        return first + rest

    @staticmethod
    def _random_cert_dname() -> str:
        """A neutral, randomized certificate subject. Avoids every generated
        APK sharing an identical ``CN=WebToApp ...`` subject, which would be
        another easy bulk-fingerprint signal for AV engines."""
        cn = "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(12))
        return f"CN={cn}"

    def _generate_keystore(self, keystore: Path, password: str, alias: str, dname: str):
        keystore.parent.mkdir(parents=True, exist_ok=True)
        _run_tool(
            [
                "keytool",
                "-J-Djava.security.egd=file:/dev/urandom",
                "-genkeypair",
                "-v",
                "-storetype",
                "PKCS12",
                "-keystore",
                str(keystore),
                "-alias",
                alias,
                "-keyalg",
                "RSA",
                "-keysize",
                "2048",
                # Self-signed cert signed with SHA1withRSA. Real-device testing
                # showed AV engines flag the SHA256withRSA self-signed certs that
                # modern toolchains (apksigner/keytool defaults) emit, while the
                # older SHA1 cert signature (what MT Manager produces) is not
                # flagged. This only affects the certificate's OWN signature; the
                # v2/v3 APK content digests remain SHA-256.
                "-sigalg",
                "SHA1withRSA",
                "-validity",
                "36500",
                "-storepass",
                password,
                "-keypass",
                password,
                "-dname",
                dname,
            ],
            check=True,
            capture_output=True,
        )

    # Signing material only depends on the keystore, which is stable across
    # rebuilds of the same app. The export used to fork 6-7 openssl processes
    # per build; cache the DER bytes + PEM texts in memory (bounded LRU) and
    # just re-materialize the two PEM files into the caller's tmp dir.
    # Deliberately NO plaintext key cache on disk — memory only, keyed by the
    # keystore's content identity so a rotated key invalidates automatically.
    _SIGNING_MATERIAL_CACHE_MAX = 256
    _signing_material_cache: "OrderedDict[tuple, tuple]" = OrderedDict()
    _signing_material_lock = threading.Lock()

    def _export_signing_material(self, keystore: Path, password: str, alias: str, tmp: Path):
        """Export (key_pem, cert_pem, key_der, cert_der, pubkey_der) from a
        PKCS12 keystore so our custom v1/v2/v3 signer (openssl-based) can use it."""
        stat = keystore.stat()
        cache_key = (str(keystore), stat.st_mtime_ns, stat.st_size, password, alias)
        with self._signing_material_lock:
            cached = self._signing_material_cache.get(cache_key)
            if cached is not None:
                self._signing_material_cache.move_to_end(cache_key)
        if cached is not None:
            key_pem_text, cert_pem_text, key_der, cert_der, pub_der = cached
            key_pem = tmp / "key.pem"
            cert_pem = tmp / "cert.pem"
            key_pem.write_text(key_pem_text)
            cert_pem.write_text(cert_pem_text)
            return key_pem, cert_pem, key_der, cert_der, pub_der
        p12 = tmp / "ks.p12"
        shutil.copy(keystore, p12)
        key_pem = tmp / "key.pem"
        cert_pem = tmp / "cert.pem"
        # private key (unencrypted PEM)
        _run_tool(
            ["openssl", "pkcs12", "-in", str(p12), "-nodes", "-nocerts",
             "-passin", f"pass:{password}", "-out", str(key_pem)],
            check=True, capture_output=True,
        )
        # leaf certificate (PEM)
        _run_tool(
            ["openssl", "pkcs12", "-in", str(p12), "-nokeys", "-clcerts",
             "-passin", f"pass:{password}", "-out", str(cert_pem)],
            check=True, capture_output=True,
        )
        key_der = tmp / "key.der"
        cert_der = tmp / "cert.der"
        pub_der = tmp / "pub.der"
        _run_tool(["openssl", "pkcs8", "-topk8", "-nocrypt", "-in", str(key_pem),
                        "-outform", "DER", "-out", str(key_der)], check=True, capture_output=True)
        _run_tool(["openssl", "x509", "-in", str(cert_pem), "-outform", "DER",
                        "-out", str(cert_der)], check=True, capture_output=True)
        pub_pem = _run_tool(["openssl", "x509", "-in", str(cert_pem), "-noout", "-pubkey"],
                                 check=True, capture_output=True).stdout
        (tmp / "pub.pem").write_bytes(pub_pem)
        res = _run_tool(["openssl", "rsa", "-pubin", "-in", str(tmp / "pub.pem"),
                              "-outform", "DER", "-out", str(pub_der)], capture_output=True)
        if res.returncode != 0:
            _run_tool(["openssl", "pkey", "-pubin", "-in", str(tmp / "pub.pem"),
                            "-outform", "DER", "-out", str(pub_der)], check=True, capture_output=True)
        key_der_bytes = key_der.read_bytes()
        cert_der_bytes = cert_der.read_bytes()
        pub_der_bytes = pub_der.read_bytes()
        with self._signing_material_lock:
            self._signing_material_cache[cache_key] = (
                key_pem.read_text(), cert_pem.read_text(),
                key_der_bytes, cert_der_bytes, pub_der_bytes,
            )
            self._signing_material_cache.move_to_end(cache_key)
            while len(self._signing_material_cache) > self._SIGNING_MATERIAL_CACHE_MAX:
                self._signing_material_cache.popitem(last=False)
        return key_pem, cert_pem, key_der_bytes, cert_der_bytes, pub_der_bytes

    def _patch_template_apk(self, template_apk: Path, output: Path, url: str, name: str, pkg: str, icon_png, version_code: int, version_name: str, feature_options: dict, app_id: str = None):
        """Produce a per-app APK by copying the cached template and patching it
        in place — no apktool decode/rebuild round-trip.

        apktool spent ~1.8 s per build decoding the template to text and
        re-encoding it, yet the patch set is tiny: the manifest's package /
        version / label, one JSON asset and the launcher icon. All of those
        live in plain ZIP entries, so the per-app APK is now a byte-level
        rewrite of three entries followed by re-alignment and re-signing:

        - AndroidManifest.xml: AXML string-pool edit + versionCode int patch
        - assets/webtoapp_config.json: rewritten wholesale
        - res/mipmap/ic_launcher.png: rewritten wholesale

        The template's stale v1 signature files are dropped; build_v1 writes
        a fresh set over the per-app key.
        """
        keystore, password, alias = self._ensure_app_keystore(app_id or pkg)

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            patched = tmp / "app-patched.apk"
            self._patch_apk_entries(
                template_apk,
                patched,
                manifest=self._patched_manifest_xml(
                    template_apk, pkg, version_code, version_name, name
                ),
                replacements={
                    "assets/webtoapp_config.json": self._config_json(url, feature_options).encode("utf-8"),
                    **({"res/mipmap/ic_launcher.png": icon_png} if icon_png else {}),
                },
            )

            built_aligned = tmp / "app-aligned.apk"
            self._align_apk(patched, built_aligned)

            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(built_aligned, output)
            # Custom signing: write v1 (JAR) ourselves with a Gradle-style
            # Created-By, then append v2+v3 blocks. This avoids apksigner's
            # hard-coded "Created-By: 1.0 (Android)" v1 string, which mobile AV
            # engines fingerprint to flag tool-signed APKs.
            key_pem, cert_pem, key_der, cert_der, pub_der = self._export_signing_material(
                keystore, password, alias, tmp
            )
            apk_v2_signer.build_v1(output, key_pem, cert_pem, alias)
            apk_v2_signer.sign_v2(output, key_der, cert_der, pub_der)

    # ===== Forkless template patching (no apktool in the per-app path) =====

    def _patched_manifest_xml(self, template_apk: Path, pkg: str, version_code: int, version_name: str, name: str) -> bytes:
        """Binary-patch the template's compiled AndroidManifest.xml (AXML).

        The template manifest is produced by our own aapt2 build and always
        carries these exact literal strings, so the patch is a constrained
        rewrite of the AXML string pool plus the versionCode attribute value:

        - package="com.webtoapp.template"  ->  pkg
        - label / versionName literal      ->  name / version_name
        - versionCode="1" int attribute    ->  version_code
        """
        with zipfile.ZipFile(template_apk, "r") as zf:
            axml = zf.read("AndroidManifest.xml")
        patched = _AxmlPatcher(axml).patch(
            {
                self.TEMPLATE_PACKAGE: pkg,
                self.TEMPLATE_APP_NAME: name,
                self.TEMPLATE_VERSION_NAME: version_name,
            },
            version_code=int(version_code),
        )
        return patched

    def _patch_apk_entries(self, source_apk: Path, output_apk: Path, manifest: bytes, replacements: dict) -> None:
        """Copy ``source_apk`` to ``output_apk`` replacing whole ZIP entries.

        The template's v1 signature (META-INF/MANIFEST.MF and the template
        keystore's .SF/.RSA) is dropped — build_v1 writes a fresh set over the
        per-app key, and a stale template MANIFEST.MF would survive as a
        duplicate entry that v1 verifiers reject. Each entry keeps the
        template's original compression (``resources.arsc`` stays STORED as
        Android requires); the final zipalign pass restores the 4-byte
        alignment the rewrite shifts around.
        """
        output_apk.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(source_apk, "r") as zin, zipfile.ZipFile(output_apk, "w") as zout:
            for info in zin.infolist():
                if info.filename == "AndroidManifest.xml":
                    data = manifest
                elif info.filename in replacements:
                    data = replacements[info.filename]
                elif info.filename == "META-INF/MANIFEST.MF" or (
                    info.filename.startswith("META-INF/") and info.filename.upper().endswith((".SF", ".RSA"))
                ):
                    continue
                else:
                    data = zin.read(info.filename)
                zinfo = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                zinfo.compress_type = info.compress_type
                zinfo.external_attr = info.external_attr
                zout.writestr(zinfo, data)

    def _align_apk(self, source: Path, output: Path) -> None:
        zipalign = self._find_tool("zipalign")
        output.parent.mkdir(parents=True, exist_ok=True)
        if zipalign:
            _run_tool([zipalign, "-f", "4", str(source), str(output)], check=True, capture_output=True)
            return
        self._python_zipalign(source, output, alignment=4)

    def _python_zipalign(self, source: Path, output: Path, alignment: int = 4) -> None:
        """Align stored ZIP entries without relying on the external zipalign tool."""
        alignment = max(1, int(alignment or 1))
        tmp_output = output.with_suffix(output.suffix + ".tmp")
        if tmp_output.exists():
            tmp_output.unlink()
        with zipfile.ZipFile(source, "r") as zin, open(tmp_output, "wb") as raw_fp:
            with zipfile.ZipFile(raw_fp, "w") as zout:
                zout.comment = zin.comment
                for info in zin.infolist():
                    zinfo = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                    zinfo.compress_type = info.compress_type
                    zinfo.comment = getattr(info, "comment", b"")
                    zinfo.extra = info.extra or b""
                    zinfo.create_system = info.create_system
                    zinfo.create_version = info.create_version
                    zinfo.extract_version = info.extract_version
                    zinfo.flag_bits = info.flag_bits
                    zinfo.volume = info.volume
                    zinfo.internal_attr = info.internal_attr
                    zinfo.external_attr = info.external_attr
                    zinfo.header_offset = 0

                    if info.is_dir():
                        zout.writestr(zinfo, b"")
                        continue

                    data = zin.read(info.filename)
                    if info.compress_type == zipfile.ZIP_STORED:
                        extra = self._alignment_extra(zout.fp.tell(), info.filename, zinfo.extra, alignment)
                        zinfo.extra = zinfo.extra + extra
                    zout.writestr(zinfo, data)
        tmp_output.replace(output)

    def _alignment_extra(self, current_offset: int, filename: str, existing_extra: bytes, alignment: int) -> bytes:
        """Return a valid extra-field padding block that keeps the next file aligned."""
        alignment = max(1, int(alignment or 1))
        name_len = len(str(filename or "").encode("utf-8"))
        extra_len = len(existing_extra or b"")
        pad_data_len = (alignment - ((current_offset + 30 + name_len + extra_len + 4) % alignment)) % alignment
        return b"\xff\xff" + pad_data_len.to_bytes(2, "little") + (b"\x00" * pad_data_len)

    def _validate_built_apk(self, apk_path: Path) -> bool:
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                arsc = zf.getinfo("resources.arsc")
                if arsc.compress_type != zipfile.ZIP_STORED:
                    return False
                offset = self._zip_data_offset(zf, arsc)
                if offset % 4 != 0:
                    return False
                dex = zf.getinfo("classes.dex")
                if self._zip_data_offset(zf, dex) % 4 != 0:
                    return False
            return True
        except Exception:
            return False

    def _zip_data_offset(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> int:
        fp = zf.fp
        if fp is None:
            raise RuntimeError("zip file is closed")
        fp.seek(info.header_offset)
        header = fp.read(30)
        _, _, _, _, _, _, _, _, _, name_len, extra_len = struct.unpack("<IHHHHHIIIHH", header)
        return info.header_offset + 30 + name_len + extra_len

    def _run_aapt2_with_fallback(self, candidates, compiled, tmp, manifest, jar, apk_unsigned):
        for aapt2 in candidates:
            try:
                res_zip = compiled / "res.zip"
                if res_zip.exists():
                    res_zip.unlink()
                if apk_unsigned.exists():
                    apk_unsigned.unlink()
                _run_tool([aapt2, "compile", "-o", str(res_zip), "--dir", str(tmp / "res")], check=True, capture_output=True)
                _run_tool([aapt2, "link", "-o", str(apk_unsigned), "-I", jar, "--manifest", str(manifest), str(res_zip)], check=True, capture_output=True)
                return aapt2
            except subprocess.CalledProcessError as e:
                print(f"[ApkBuilder] aapt2 {aapt2} failed (exit={e.returncode}), trying next version")
                continue
        return None

    def build_fallback(self, output, url, name, icon_png=None, color="#000000"):
        # All user-controlled values get context-appropriate encoding before
        # they land in the package — same hardening as the generated pages.
        name_esc = html.escape(str(name or ""), quote=True)
        color_safe = str(color or "") if re.fullmatch(r"#[0-9A-Fa-f]{3,8}", str(color or "")) else "#000000"
        parsed = urlparse(str(url or "").strip())
        url_safe = str(url).strip() if parsed.scheme.lower() in ("http", "https") and parsed.netloc else "about:blank"
        url_esc = html.escape(url_safe, quote=True)
        dir_name = re.sub(r'[\\/:*?"<>|$`\'\[\]\x00-\x1f]', "_", str(name or "")).strip(" .")[:80] or "app"
        manifest = {
            "name": name,
            "short_name": name[:12],
            "start_url": url_safe,
            "display": "fullscreen",
            "background_color": color_safe,
            "theme_color": color_safe,
            "icons": [{"src": "icon.png", "sizes": "256x256", "type": "image/png"}] if icon_png else [],
        }
        html_doc = f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="{color_safe}">
<meta name="apple-mobile-web-app-capable" content="yes">
<title>{name_esc}</title><link rel="manifest" href="manifest.json">
<style>*{{margin:0}}html,body,iframe{{width:100%;height:100%;border:0;overflow:hidden}}</style>
</head><body>
<iframe src="{url_esc}" allow="fullscreen"></iframe>
<script>if('serviceWorker' in navigator)navigator.serviceWorker.register('sw.js');</script>
</body></html>"""
        sw = "self.addEventListener('fetch',e=>{e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)))});"
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr(f"{dir_name}/index.html", html_doc)
            z.writestr(f"{dir_name}/manifest.json", json.dumps(manifest, ensure_ascii=False))
            z.writestr(f"{dir_name}/sw.js", sw)
            if icon_png:
                z.writestr(f"{dir_name}/icon.png", icon_png)
            z.writestr(
                f"{dir_name}/README.txt",
                f"【{name} — Android 安装指南】\n\n"
                f"方法一：将此文件夹部署到任意 HTTPS 服务器，用 Chrome 打开后点击「添加到主屏幕」\n"
                f"方法二：直接在浏览器中访问 {url_safe}\n",
            )

    def _config_json(self, url: str, feature_options: dict) -> str:
        raw = feature_options or {}
        payload = {
            "url": str(url or "").strip() or "about:blank",
            "immersive_fullscreen": bool(
                raw.get("feature-immersive-fullscreen") or raw.get("feature_immersive_fullscreen")
            ),
            "desktop_mode": bool(
                raw.get("feature-desktop-mode") or raw.get("feature_desktop_mode")
            ),
            # Extra ad hosts injected per-build by the server. Passed through to
            # the APK's webtoapp_config.json asset and loaded at runtime by
            # AppConfig so site-specific domains can be blocked without a
            # template rebuild.
            "extra_ad_hosts": list(raw.get("extra_ad_hosts") or []),
            "tv_mode": bool(
                raw.get("feature-tv-mode") or raw.get("feature_tv_mode")
            ),
            "tv_auto_fullscreen": bool(
                raw.get("feature-tv-auto-fullscreen") or raw.get("feature_tv_auto_fullscreen")
            ),
            "tv_remote": bool(
                raw.get("feature-tv-remote") or raw.get("feature_tv_remote")
            ),
            "tv_subtitles": bool(
                raw.get("feature-tv-subtitles") or raw.get("feature_tv_subtitles")
            ),
            "tv_nav_hosts": list(
                raw.get("feature-tv-extra-hosts") or raw.get("feature_tv_extra_hosts") or []
            ),
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    def _blank_png(self):
        size = 128
        rgba = (124, 58, 237, 255)
        ihdr_data = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
        ihdr = b"IHDR" + ihdr_data
        ihdr_chunk = struct.pack(">I", len(ihdr_data)) + ihdr + struct.pack(">I", zlib.crc32(ihdr))
        raw = b"".join(b"\x00" + bytes(rgba) * size for _ in range(size))
        idat_data = zlib.compress(raw, 9)
        idat = b"IDAT" + idat_data
        idat_chunk = struct.pack(">I", len(idat_data)) + idat + struct.pack(">I", zlib.crc32(idat))
        iend_chunk = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND"))
        return b"\x89PNG\r\n\x1a\n" + ihdr_chunk + idat_chunk + iend_chunk


