def get_form_dictionary(rq):
    try:
        args = rq.form.to_dict()
        return args
    except Exception:
        return None
