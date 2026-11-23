;(function () {
  function esc(s) {
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
  }

  function escAttr(s) {
    return esc(s).replace(/`/g, '&#96;')
  }

  function safeUrl(url) {
    url = String(url || '').trim()
    if (!url) return null
    if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(url) && !/^https?:/i.test(url)) return null
    if (/^javascript:/i.test(url)) return null
    return url
  }

  function renderInline(text) {
    var s = text
    s = s.replace(/`([^`]+)`/g, function (_, code) {
      return '<code class="km-md-code-inline">' + esc(code) + '</code>'
    })
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    s = s.replace(/\*([^*]+)\*/g, '<em>$1</em>')
    s = s.replace(/\[([^\]]+)\]\(([^)]+)\)/g, function (_, label, url) {
      var u = safeUrl(url)
      if (!u) return esc(label)
      return '<a href="' + escAttr(u) + '" class="km-md-link">' + esc(label) + '</a>'
    })
    return s
  }

  function render(md) {
    md = String(md || '').replace(/\r\n/g, '\n')
    var blocks = []
    var tokenPrefix = '@@KM_CODE_BLOCK_'
    var tokenSuffix = '@@'

    md = md.replace(/```([a-zA-Z0-9_-]+)?\n([\s\S]*?)```/g, function (_, lang, code) {
      var i = blocks.length
      var l = (lang || '').trim().toLowerCase()
      var cls = l ? 'language-' + l : ''
      blocks.push(
        '<pre class="km-md-pre ' +
          cls +
          '"><code class="km-md-code ' +
          cls +
          '">' +
          esc(code) +
          '</code></pre>'
      )
      return tokenPrefix + i + tokenSuffix
    })

    md = esc(md)
    var lines = md.split('\n')
    var out = []
    var para = []

    function flushPara() {
      if (!para.length) return
      out.push('<p class="km-md-p">' + renderInline(para.join('<br>')) + '</p>')
      para = []
    }

    function tokenToBlock(s) {
      return s.replace(new RegExp(tokenPrefix + '(\\d+)' + tokenSuffix, 'g'), function (_, idx) {
        var n = parseInt(idx, 10)
        return blocks[n] || ''
      })
    }

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i]
      if (!line.trim()) {
        flushPara()
        continue
      }

      var m = line.match(/^(#{1,6})\s+(.+)$/)
      if (m) {
        flushPara()
        var level = m[1].length
        out.push('<h' + level + ' class="km-md-h' + level + '">' + renderInline(m[2].trim()) + '</h' + level + '>')
        continue
      }

      if (/^>\s?/.test(line)) {
        flushPara()
        var parts = []
        while (i < lines.length && /^>\s?/.test(lines[i])) {
          parts.push(lines[i].replace(/^>\s?/, ''))
          i++
        }
        i--
        out.push('<blockquote class="km-md-quote">' + renderInline(parts.join('<br>')) + '</blockquote>')
        continue
      }

      if (/^(\s*[-*])\s+/.test(line)) {
        flushPara()
        var items = []
        while (i < lines.length && /^(\s*[-*])\s+/.test(lines[i])) {
          items.push(lines[i].replace(/^(\s*[-*])\s+/, ''))
          i++
        }
        i--
        out.push(
          '<ul class="km-md-ul">' +
            items
              .map(function (x) {
                return '<li class="km-md-li">' + renderInline(x) + '</li>'
              })
              .join('') +
            '</ul>'
        )
        continue
      }

      if (/^\d+\.\s+/.test(line)) {
        flushPara()
        var oitems = []
        while (i < lines.length && /^\d+\.\s+/.test(lines[i])) {
          oitems.push(lines[i].replace(/^\d+\.\s+/, ''))
          i++
        }
        i--
        out.push(
          '<ol class="km-md-ol">' +
            oitems
              .map(function (x) {
                return '<li class="km-md-li">' + renderInline(x) + '</li>'
              })
              .join('') +
            '</ol>'
        )
        continue
      }

      if (line.indexOf(tokenPrefix) !== -1) {
        flushPara()
        out.push(tokenToBlock(line))
        continue
      }

      para.push(line)
    }

    flushPara()
    return tokenToBlock(out.join(''))
  }

  window.kmMarkdownLite = { render: render }
})()

