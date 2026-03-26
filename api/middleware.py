from django.conf import settings
import threading


class EnsureAmlDatasetMiddleware:
    """Warm analysis/analytics cache from transactions_dataset.csv when it is empty."""
    _warm_started = False
    _warm_lock = threading.Lock()

    def __init__(self, get_response):
        self.get_response = get_response

    @classmethod
    def _trigger_background_warmup(cls):
        with cls._warm_lock:
            if cls._warm_started:
                return
            cls._warm_started = True

        def _worker():
            try:
                from api.views import ensure_aml_dataset_ready

                ensure_aml_dataset_ready()
            finally:
                # Allow future retries if warmup fails for any reason.
                with cls._warm_lock:
                    cls._warm_started = False

        threading.Thread(target=_worker, daemon=True).start()

    def __call__(self, request):
        if getattr(settings, "AML_AUTO_SYNC_DATASET", True) and request.method in ("GET", "HEAD"):
            path = request.path
            if (
                not path.startswith("/static/")
                and path != "/favicon.ico"
                and not path.startswith("/admin/")
            ):
                # Non-blocking warmup so first page load is fast.
                self._trigger_background_warmup()
        return self.get_response(request)
