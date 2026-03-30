AUTO_DETECT_SHIM = True

from railway_entry import load_application, run_dev_server


ENTRY_MODULE, app, APP_KIND = load_application()


if __name__ == "__main__":
    run_dev_server(ENTRY_MODULE, app, APP_KIND)
