"""
Configuração de retry com backoff exponencial para erros transitórios de rede/API.
"""

import httpx
from tenacity import (
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from ..exceptions import PaloAltoTimeoutError


def is_transient_error(exception: BaseException) -> bool:
    """Verifica se a exceção é transitória e elegível para nova tentativa."""
    if isinstance(exception, (httpx.TimeoutException, PaloAltoTimeoutError)):
        return True
    if isinstance(exception, httpx.NetworkError):
        return True
    if isinstance(exception, httpx.HTTPStatusError):
        # 502 Bad Gateway, 503 Service Unavailable, 504 Gateway Timeout
        return exception.response.status_code in {502, 503, 504}
    return False


panos_retry = retry(
    retry=retry_if_exception(is_transient_error),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    reraise=True,
)
