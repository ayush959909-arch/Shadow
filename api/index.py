"""ShadowX - URL / screenshot / SMS / email / APK scanner (FastAPI) for Vercel.
from typing import Optional
from email import message_from_string, policy
from email.utils import parseaddr
import html as html_lib

app = FastAPI(title="ShadowX")
VT_KEY = os.getenv("VT_API_KEY")
GSB_KEY = os.getenv("GSB_API_KEY")

BRANDS = ["sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay", "google", "amazon",
          "flipkart", "paypal", "microsoft", "apple", "netflix", "instagram", "facebook",
          "whatsapp", "irctc", "uidai", "incometax"]
RISKY_TLDS = {"xyz", "top", "click", "icu", "buzz", "tk", "ml", "ga", "cf", "gq", "work",
              "loan", "rest", "cyou", "sbs", "lol", "zip", "mov"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at", "goo.gl"}
TWO_PART = {"co.in", "org.in", "gov.in", "net.in", "ac.in", "co.uk", "com.au", "com.br"}
UA = {"User-Agent": "Mozilla/5.0 (ShadowX scanner)"}


class Req(BaseModel):
    kind: str = "url"
    url: str = ""
    text: str = ""
    sender: str = ""
    apk: Optional[dict] = None

