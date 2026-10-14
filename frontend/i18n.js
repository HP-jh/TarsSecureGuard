/**
 * TSG i18n Client v4.9.0
 * 功能：加载翻译包 / localStorage缓存 / WebSocket实时更新 / DOM自动翻译 / 插值 / 复数
 */
(function(global){
  'use strict';
  const CACHE_KEY = 'tsg_i18n_';
  const CACHE_VER_KEY = 'tsg_i18n_ver';
  const CACHE_TS_KEY = 'tsg_i18n_ts';
  const CACHE_TTL = 7 * 24 * 3600 * 1000; // 7天
  const REFRESH_INTERVAL = 5 * 60 * 1000; // 5分钟轮询兜底

  class I18nClient {
    constructor() {
      this.lang = this.detectLang();
      this.messages = {};
      this.fallback = 'en';
      this.version = '';
      this.ws = null;
      this.wsTimer = null;
      this._listeners = [];
    }

    // ========== 初始化 ==========
    async init() {
      // 1. 先读缓存
      this.loadCache();
      // 2. 拉最新
      await this.fetchBundle(this.lang);
      // 3. 启动 WebSocket
      this.connectWS();
      // 4. 定时轮询兜底
      setInterval(() => this.fetchBundle(this.lang, true), REFRESH_INTERVAL);
      // 5. 首次翻译 DOM
      this.translateDOM();
    }

    // ========== 语言检测 ==========
    detectLang() {
      // 优先用户手动选择
      const saved = localStorage.getItem('tsg_lang');
      if (saved && this.isSupported(saved)) return saved;
      // 其次系统语言
      const nav = navigator.language || navigator.userLanguage || 'en';
      const code = nav.toLowerCase();
      const map = {
        'zh': 'zh-CN', 'zh-cn': 'zh-CN', 'zh-tw': 'zh-CN', 'zh-hk': 'zh-CN',
        'en': 'en', 'en-us': 'en', 'en-gb': 'en',
        'ja': 'ja-JP', 'jp': 'ja-JP',
        'ko': 'ko-KR', 'kr': 'ko-KR',
        'es': 'es', 'es-es': 'es', 'es-mx': 'es',
        'fr': 'fr', 'fr-fr': 'fr'
      };
      const mapped = map[code] || map[code.split('-')[0]];
      if (mapped && this.isSupported(mapped)) return mapped;
      return 'en';
    }

    isSupported(code) {
      return ['zh-CN','en','ja-JP','ko-KR','es','fr'].includes(code);
    }

    // ========== 加载缓存 ==========
    loadCache() {
      try {
        const ts = parseInt(localStorage.getItem(CACHE_TS_KEY + this.lang) || '0', 10);
        if (Date.now() - ts > CACHE_TTL) return;
        const raw = localStorage.getItem(CACHE_KEY + this.lang);
        if (!raw) return;
        const data = JSON.parse(raw);
        if (data && data.messages) {
          this.messages = data.messages;
          this.version = data.meta && data.meta.version || '';
        }
      } catch(e) {}
    }

    saveCache(lang, data) {
      try {
        localStorage.setItem(CACHE_KEY + lang, JSON.stringify(data));
        localStorage.setItem(CACHE_VER_KEY + lang, data.meta && data.meta.version || '');
        localStorage.setItem(CACHE_TS_KEY + lang, String(Date.now()));
      } catch(e) {}
    }

    // ========== 拉取翻译包 ==========
    async fetchBundle(lang, silent=false) {
      try {
        const res = await fetch('/api/i18n/bundle?lang=' + encodeURIComponent(lang), {
          headers: { 'Accept': 'application/json' }
        });
        if (!res.ok) return;
        const data = await res.json();
        const newVer = data.meta && data.meta.version;
        // 版本没变且已有缓存则跳过
        if (silent && newVer && this.version === newVer && Object.keys(this.messages).length > 0) return;
        this.messages = data.messages || {};
        this.fallback = data.fallback || 'en';
        this.version = newVer || '';
        this.saveCache(lang, data);
        if (!silent) this.translateDOM();
      } catch(e) {
        if (!silent) console.warn('[i18n] fetch bundle failed:', e);
      }
    }

    // ========== SSE 实时推送 ==========
    connectWS() {
      const url = '/api/i18n/stream?lang=' + this.lang;
      try {
        const es = new EventSource(url);
        this.ws = es;
        es.onopen = () => { this.setWSStatus('connected'); };
        es.addEventListener('update', (ev) => {
          try {
            const msg = JSON.parse(ev.data);
            if (msg.type === 'update' && (msg.lang === '*' || msg.lang === this.lang)) {
              this.fetchBundle(this.lang, true);
            }
          } catch(e) {}
        });
        es.onerror = () => {
          this.setWSStatus('reconnecting');
          es.close();
          this.wsTimer = setTimeout(() => this.connectWS(), 5000);
        };
      } catch(e) {}
    }

    setWSStatus(status) {
      document.querySelectorAll('[data-i18n-ws]').forEach(el => {
        el.textContent = this.t('ws.status.' + status);
        el.className = 'ws-badge ' + status;
      });
    }

    // ========== 翻译核心 ==========
    t(key, args) {
      let val = this.messages[key];
      if (!val && this.lang !== this.fallback) {
        // fallback 到英文（尝试从缓存或简单内置）
        val = this._fallbackMsg(key);
      }
      if (!val) return key;
      if (args) {
        val = val.replace(/\{\{(\w+)\}\}/g, (_, k) => args[k] !== undefined ? args[k] : '{{'+k+'}}');
      }
      return val;
    }

    _fallbackMsg(key) {
      // 极简内置英文兜底（高频 key）
      const fb = {
        'ws.status.connected':'Connected','ws.status.disconnected':'Disconnected','ws.status.reconnecting':'Reconnecting...',
        'common.save':'Save','common.cancel':'Cancel','common.confirm':'Confirm','common.delete':'Delete',
        'common.loading':'Loading...','common.empty':'No data','common.error':'Error','common.success':'Success'
      };
      return fb[key] || '';
    }

    // ========== DOM 自动翻译 ==========
    translateDOM(root) {
      root = root || document.body;
      // data-i18n="key"
      root.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (!key) return;
        const val = this.t(key, this._parseArgs(el.dataset.i18nArgs));
        if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA') {
          if (el.placeholder !== undefined) el.placeholder = val;
        } else if (el.title && el.hasAttribute('data-i18n-title')) {
          el.title = val;
        } else {
          el.textContent = val;
        }
      });
      // data-i18n-title
      root.querySelectorAll('[data-i18n-title]').forEach(el => {
        const key = el.getAttribute('data-i18n-title');
        if (key) el.title = this.t(key);
      });
      // data-i18n-placeholder
      root.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        if (key) el.placeholder = this.t(key);
      });
      // html lang 属性
      document.documentElement.lang = this.lang;
    }

    _parseArgs(raw) {
      if (!raw) return null;
      try { return JSON.parse(raw); } catch(e) { return null; }
    }

    // ========== 语言切换 ==========
    async switchLang(code) {
      if (!this.isSupported(code) || code === this.lang) return;
      this.lang = code;
      localStorage.setItem('tsg_lang', code);
      // 重连 SSE
      if (this.ws) { try { this.ws.close(); } catch(e) {} }
      if (this.wsTimer) { clearTimeout(this.wsTimer); }
      this.connectWS();
      // 拉新包
      await this.fetchBundle(code);
      this.translateDOM();
      // 通知监听者
      this._listeners.forEach(fn => fn(code));
    }

    onChange(fn) { this._listeners.push(fn); }

    // ========== 翻译完成度仪表盘（前端渲染用）==========
    async loadDashboard() {
      try {
        const res = await fetch('/api/i18n/dashboard');
        if (!res.ok) return null;
        return await res.json();
      } catch(e) { return null; }
    }
  }

  // 全局单例
  const i18n = new I18nClient();
  global.i18n = i18n;

  // DOMReady 后自动初始化
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => i18n.init());
  } else {
    i18n.init();
  }
})(window);
