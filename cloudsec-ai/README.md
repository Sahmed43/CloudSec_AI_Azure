# CloudSec AI — Azure OpenAI Security Triage Lab

**CI:** `.github/workflows/ci.yml` runs lint and unit tests on pushes and pull requests.

**A working Python security triage application with optional real Azure OpenAI integration.**

> **Scope:** Local CSV analysis and a Streamlit dashboard work without Azure. Real Azure OpenAI
> summarization works only after you configure an Azure resource, deploy a compatible model,
> and supply credentials. No live Microsoft Sentinel ingestion or Azure deployment is claimed.

## What it does

- Validates synthetic event CSVs (up to 5 MB / 10,000 events).
- Detects 5+ failed logins from the same user/IP in 10 minutes, successful sign-ins from
  different locations within 30 minutes, and successful privileged configuration changes.
- Displays event and finding tables in Streamlit.
- Uses **real Azure OpenAI chat completions** on analyst request to explain heuristic findings,
  possible false positives, and human validation steps.
- Generates a local JSON report using the CLI.
- Includes pytest unit tests, mocked Azure AI integration test, GitHub Actions CI, and Dockerfile.

## Prerequisites

Python 3.10+ (Python 3.11 recommended), Git, and optionally an Azure subscription with access
to an Azure OpenAI resource and a deployed chat-capable model. Model availability, access,
regional support, quotas, and billing depend on your Azure subscription. Never commit keys.

## 1. Run locally (Windows PowerShell)

Extract the ZIP, open PowerShell **inside this folder**, and run:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pytest -q
streamlit run app/streamlit_app.py
```

If Python 3.11 isn't installed, replace `py -3.11` with a working Python 3.10+ command.
If PowerShell blocks activation, use `.venv\Scripts\python.exe -m pip install -e ".[dev]"`
and `.venv\Scripts\python.exe -m streamlit run app/streamlit_app.py` instead.

Open the local URL printed by Streamlit (normally http://localhost:8501).
The dashboard loads `data/synthetic_events.csv` by default.

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
pytest -q
streamlit run app/streamlit_app.py
```

## 2. Enable real Azure OpenAI

1. In the [Azure portal](https://portal.azure.com/), create or select an Azure OpenAI resource
   (the portal may surface Azure AI Foundry / Microsoft Foundry experiences depending on your tenant).
2. Deploy a **chat-completions-compatible model** to that resource. Record the **deployment name**
   (which can differ from the underlying model name). Ensure your deployment supports the chosen
   API version. If the portal offers only newer API versions, update the setting accordingly.
3. In your resource's **Keys and Endpoint** area, copy the resource endpoint and one API key.
   The endpoint should look like `https://YOUR-RESOURCE.openai.azure.com/`, not a model URL.
4. Copy `.env.example` to `.env` and replace the placeholders:

   ```powershell
   Copy-Item .env.example .env
   notepad .env
   ```

   ```dotenv
   AZURE_OPENAI_ENDPOINT=https://YOUR-RESOURCE.openai.azure.com/
   AZURE_OPENAI_API_KEY=YOUR_REAL_KEY
   AZURE_OPENAI_DEPLOYMENT=YOUR_DEPLOYMENT_NAME
   AZURE_OPENAI_API_VERSION=2024-10-21
   ```

5. Restart Streamlit, then click **Run Azure OpenAI analysis**. This makes a real billed API
   request. The `openai` Python package's `AzureOpenAI` client sends the request to your
   configured Azure resource using the deployment name in the `model` argument.

**Troubleshooting:** 401/403 = key, endpoint, access, or policy; 404 = wrong deployment/endpoint
or incompatible API version; 429 = quota/rate limit; timeout = network/connectivity. Verify
API version compatibility in current Azure docs if your deployment rejects `2024-10-21`.

Official documentation: [Azure OpenAI Python chat completions](https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/chatgpt?tabs=python-new),
[Azure OpenAI authentication](https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/switching-endpoints).

## 3. CLI report

```powershell
cloudsec --input data/synthetic_events.csv --output report.json
cloudsec --input data/synthetic_events.csv --output report.json --ai
```

The first command works offline; `--ai` uses Azure OpenAI and can incur charges.
`report.json` is excluded by `.gitignore`.

## 4. Run tests and lint

```powershell
pytest -q
ruff check src tests app
```

The AI test mocks the Azure API; tests do not require an Azure subscription or API key.
A passing mocked test does **not** prove a real cloud request succeeded.

## 5. Optional Docker deployment

```bash
docker build -t cloudsec-ai:local .
docker run --rm -p 8501:8501 cloudsec-ai:local
```

To test real AI with Docker, pass your environment settings securely at runtime, e.g.
`docker run --rm --env-file .env -p 8501:8501 cloudsec-ai:local` on a trusted local machine.
Do not bake `.env` into the image or upload it to GitHub.

### Optional Azure Container Apps deployment (manual)

Use the Azure portal to create an Azure Container Registry (ACR), push the Docker image,
then create a Container App from that registry image. Set ingress to port `8501` and configure
Azure OpenAI settings as **Container Apps secrets** with environment-variable references.
Restrict ingress/authentication before exposing the app; the included Streamlit demo has
**no login system**. Costs can accrue for Container Apps, ACR, and Azure OpenAI.

Azure docs: [Deploy container apps](https://learn.microsoft.com/en-us/azure/container-apps/overview),
[Container Apps secrets](https://learn.microsoft.com/en-us/azure/container-apps/manage-secrets).

## 6. Upload all nested folders to GitHub

1. Create a new **empty** repository called `cloudsec-ai` on GitHub (avoid adding a README first).
2. Extract the ZIP. Open the **inner `cloudsec-ai` folder** containing `pyproject.toml`, `src`,
   `tests`, `app`, and `.github`.
3. Recommended (preserves hidden `.github` workflow and nested directories):

   ```powershell
   git init
   git add .
   git commit -m "Initial CloudSec AI portfolio project"
   git branch -M main
   git remote add origin https://github.com/YOUR_USERNAME/cloudsec-ai.git
   git push -u origin main
   ```

   Replace `YOUR_USERNAME` with your GitHub account name. GitHub may prompt you to authenticate.
   Alternatively, drag the extracted project folders into **Add file → Upload files**; verify
   `.github/workflows/ci.yml` is included. Git does not track empty directories.
4. On GitHub, open **Actions** to verify the CI workflow passed.

## Portfolio demo script

1. Show synthetic CSV input and explain that documentation-only IP ranges are used.
2. Run tests and display the dashboard.
3. Show repeated failed sign-ins, multi-location sign-ins, and privilege changes.
4. Configure your Azure OpenAI deployment privately and click **Run Azure OpenAI analysis**.
5. Explain that AI is used for analyst support, not autonomous incident response.

## Ethical / technical limitations

The demo uses simplified heuristic rules. It is not a production SOC platform, does not
calculate travel speed or enrich IP reputation, and does not automatically remediate incidents.
AI can hallucinate; a human must validate outputs. Only send synthetic or authorized data.
The default example uses RFC 5737 documentation IP ranges and fabricated identities.

MIT license. See [SECURITY.md](SECURITY.md) and [docs/architecture.md](docs/architecture.md).
