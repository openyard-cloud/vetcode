// Widely used package names that typosquatters imitate, plus legitimate packages that sit
// one letter away from them (so they are not reported as lookalikes). Names are normalised:
// lower case, `_` and `.` as `-`.

import fs from "node:fs";

const list = s => new Set(s.trim().split(/\s+/).map(n => n.toLowerCase().replace(/[_.]+/g, "-")));

export const POPULAR_NPM = list(`
react react-dom react-router react-router-dom react-native react-redux redux redux-thunk redux-saga preact next nuxt vue vuex vue-router
svelte solid-js angular lit jquery lodash lodash-es underscore ramda immer immutable moment dayjs date-fns luxon axios node-fetch
cross-fetch undici got request superagent ky express koa fastify hapi restify body-parser cookie-parser cors helmet morgan
compression multer formidable busboy passport jsonwebtoken bcrypt bcryptjs argon2 crypto-js uuid nanoid shortid chalk colors
kleur picocolors commander yargs minimist inquirer prompts ora debug dotenv dotenv-expand cross-env nodemon pm2 concurrently
rimraf mkdirp glob fast-glob globby chokidar fs-extra graceful-fs semver minimatch micromatch async bluebird rxjs eventemitter3
ws socket-io socket-io-client mongoose mongodb mysql mysql2 pg pg-promise sequelize typeorm prisma knex redis ioredis sqlite3
better-sqlite3 drizzle-orm graphql apollo-server graphql-request typescript ts-node tsx esbuild webpack webpack-cli vite rollup
parcel babel-loader eslint prettier jest mocha chai sinon vitest cypress playwright puppeteer supertest nock tailwindcss postcss
autoprefixer sass less styled-components classnames clsx zod yup joi ajv validator class-validator sharp jimp canvas pdfkit
handlebars ejs pug nunjucks marked markdown-it highlight-js dompurify sanitize-html cheerio jsdom xml2js fast-xml-parser
papaparse csv-parse xlsx exceljs archiver adm-zip jszip tar node-cron cron agenda bull bullmq nodemailer twilio stripe openai
anthropic firebase firebase-admin aws-sdk electron electron-builder discord-js telegraf node-telegram-bot-api puppeteer-core
http-proxy http-proxy-middleware qs query-string path-to-regexp mime mime-types serve-static finalhandler cookie js-cookie
lru-cache node-cache keyv winston pino bunyan loglevel yaml js-yaml toml ini json5 deepmerge deep-equal fast-deep-equal
object-assign core-js regenerator-runtime tslib rxjs-compat zustand jotai recoil mobx swr react-query framer-motion three d3
chart-js echarts leaflet mapbox-gl socket-io-parser engine-io colorette ansi-styles strip-ansi string-width wrap-ansi
supports-color has-flag escape-string-regexp is-number kind-of isarray safe-buffer buffer events util process path-browserify
crypto-browserify stream-browserify node-gyp node-pre-gyp nan bindings prebuild-install esm ts-jest babel-jest jest-cli
recharts nextra vitepress react-dnd tslint react-is cookies color server prompt next-auth class-transformer prismjs
nx turbo lerna husky lint-staged commitizen semantic-release np standard-version vercel netlify-cli wrangler miniflare
`);

export const POPULAR_SCOPES = new Set(`
angular babel types nestjs vue vueuse aws-sdk smithy google-cloud googleapis azure prisma supabase tanstack reduxjs mui emotion
testing-library radix-ui sveltejs vitejs cloudflare vercel next octokit sentry firebase apollo graphql-tools storybook playwright
typescript-eslint eslint rollup swc tailwindcss headlessui heroicons fortawesome nuxt remix-run trpc hapi fastify opentelemetry
anthropic-ai openai langchain modelcontextprotocol aws-cdk aws-amplify react-native-community expo react-navigation reach
floating-ui dnd-kit hookform ai-sdk clerk auth0 stripe shopify sanity contentful strapi astrojs builder-io lit-labs chakra-ui
mantine nextui-org shadcn tiptap lexical codemirror monaco-editor xterm pnpm yarnpkg npmcli microsoft electron electron-forge
`.trim().split(/\s+/));

export const POPULAR_PYPI = list(`
requests urllib3 certifi idna charset-normalizer chardet httpx aiohttp httplib2 boto3 botocore s3transfer awscli google-cloud-storage
google-api-python-client numpy pandas scipy matplotlib seaborn plotly scikit-learn sklearn tensorflow keras torch torchvision
torchaudio transformers tokenizers datasets huggingface-hub accelerate diffusers sentencepiece safetensors openai anthropic
langchain langchain-core langchain-openai langchain-community llama-index tiktoken flask django fastapi starlette uvicorn gunicorn
werkzeug jinja2 markupsafe itsdangerous click typer rich colorama tqdm pyyaml toml tomli python-dotenv pydantic pydantic-core
attrs marshmallow sqlalchemy alembic psycopg2 psycopg2-binary psycopg pymysql mysqlclient pymongo redis celery kombu
beautifulsoup4 bs4 lxml html5lib selenium playwright scrapy pillow opencv-python opencv-python-headless imageio pytest
pytest-cov pytest-mock mock coverage tox nox black flake8 pylint mypy ruff isort pre-commit setuptools wheel pip pipenv poetry
virtualenv six python-dateutil pytz tzdata arrow pendulum cryptography pyopenssl paramiko bcrypt passlib pyjwt jwt
python-jose oauthlib requests-oauthlib websocket-client websockets grpcio protobuf docker kubernetes ansible fabric invoke
jsonschema simplejson ujson orjson msgpack cffi pycparser wrapt decorator packaging filelock platformdirs appdirs psutil
pexpect ptyprocess sh pyserial pygments docutils sphinx markdown mkdocs openpyxl xlrd xlsxwriter python-docx reportlab pypdf2
pypdf pymupdf discord-py python-telegram-bot slack-sdk twilio stripe sentry-sdk streamlit gradio dash bokeh networkx sympy
pymssql boto tomli-w httpie cchardet psycopg-binary psycopg-c psycopg-pool bpython authlib aiohttp-retry ujson-ext tox-uv
numba cython jupyter notebook ipython ipykernel jupyterlab colorlog loguru structlog tenacity backoff retrying cachetools
more-itertools toolz pyarrow polars duckdb dask xgboost lightgbm catboost statsmodels nltk spacy gensim
`);

// Bigger public rankings (names only, see the headers of the data files): every name in them is
// a real, widely used package, and the top of each list is what typosquatters imitate.
const ranked = file => { try { return fs.readFileSync(new URL(`./data/${file}`, import.meta.url), "utf8").split("\n").filter(l => l && !l.startsWith("#")).map(n => n.toLowerCase().replace(/[_.]+/g, "-")); } catch { return []; } };
const npmRanked = ranked("popular-npm.txt"), pypiRanked = ranked("popular-pypi.txt");
export const KNOWN_NPM = new Set([...POPULAR_NPM, ...npmRanked]);
export const KNOWN_PYPI = new Set([...POPULAR_PYPI, ...pypiRanked]);
export const TARGET_NPM = new Set([...POPULAR_NPM, ...npmRanked.slice(0, 1500)]);
export const TARGET_PYPI = new Set([...POPULAR_PYPI, ...pypiRanked.slice(0, 1500)]);
