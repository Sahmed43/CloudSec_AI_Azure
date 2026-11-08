from unittest.mock import MagicMock, patch
from cloudsec.ai import summarize
from cloudsec.models import Finding

def test_ai_empty_does_not_call_service():
    assert "No heuristic findings" in summarize([])

def test_ai_calls_azure_deployment(monkeypatch):
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://example.openai.azure.com/")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-not-real")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "my-gpt-deployment")
    response = MagicMock()
    response.choices[0].message.content = "Validate the alert."
    finding = Finding("TEST", "low", "Example", "Sample", ["u"], ["ip"], 1, "Review")
    with patch("cloudsec.ai.AzureOpenAI") as cls:
        cls.return_value.chat.completions.create.return_value = response
        assert summarize([finding]) == "Validate the alert."
        kwargs = cls.return_value.chat.completions.create.call_args.kwargs
        assert kwargs["model"] == "my-gpt-deployment"
        assert "untrusted" in kwargs["messages"][0]["content"]
