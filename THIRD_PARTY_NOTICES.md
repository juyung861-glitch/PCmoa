# Third-Party Notices (외부 라이브러리 저작권 표시)

이 프로젝트는 아래의 외부 소프트웨어를 포함하거나 사용합니다. 각 소프트웨어의 저작권은 원저작자에게 있으며, 해당 라이선스 조건을 따릅니다.

---

## 1. 저장소에 직접 포함된 파일 (`server/static/vendor/`)

### xterm.js — `xterm.js`, `xterm.css`
- 홈페이지: https://xtermjs.org / https://github.com/xtermjs/xterm.js
- 라이선스: MIT

```
Copyright (c) 2017-2019, The xterm.js authors (https://github.com/xtermjs/xterm.js)
Copyright (c) 2014-2016, SourceLair Private Company (https://www.sourcelair.com)
Copyright (c) 2012-2013, Christopher Jeffrey (https://github.com/chjj/)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

### @xterm/addon-fit — `addon-fit.js`
- 홈페이지: https://github.com/xtermjs/xterm.js/tree/master/addons/addon-fit
- 라이선스: MIT (위 xterm.js와 동일한 저작권자·조건)

---

## 2. 외부에서 불러오는 글꼴

### Pretendard
- 홈페이지: https://github.com/orioncactus/pretendard
- 라이선스: SIL Open Font License 1.1
- 사용 방식: `server/static/index.html`에서 CDN(jsDelivr) 링크로 불러옴. 글꼴 파일은 저장소에 포함되지 않음.

---

## 3. pip로 설치하는 Python 라이브러리 (`requirements.txt`)

저장소에 코드가 포함되지 않고 사용자가 각자 설치합니다. 참고용으로 라이선스를 적어 둡니다.

| 라이브러리 | 라이선스 |
|---|---|
| fastapi | MIT |
| uvicorn | BSD-3-Clause |
| python-multipart | Apache-2.0 |
| bcrypt | Apache-2.0 |
| cryptography | Apache-2.0 / BSD-3-Clause |
| paramiko | LGPL-2.1 |
| psutil | BSD-3-Clause |
| pywinrm | MIT |
| mss | MIT |
| pillow | MIT-CMU (HPND) |
| pynput | LGPL-3.0 |
| truststore | MIT |

> paramiko·pynput은 LGPL입니다. 이 프로젝트는 두 라이브러리를 수정하지 않고 그대로 import하여 사용하며, 사용자가 pip로 자유롭게 다른 버전으로 교체할 수 있으므로 LGPL 조건을 충족합니다.
