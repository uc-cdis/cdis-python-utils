from cdiserrors import NotFoundError


def get_value(dictionary, key, ex=None):
    """
        Get value identified by parameter key from a dictionary.

        Args:
            dictionary (Required[dict]):
                the dictionary from which value is retrieved
            key (Required[str]):
                the key that identifies value need to be got
            ex (Exception):
                the error (exception) in case the key does not exist in the dictionary

        Return:
            Either dict, list, str or number

        Raises:
            NotFoundError: if dictionary does not contains key and ex is not provided
    """
    res = dictionary.get(key)
    if res is None:
        if ex is not None:
            raise ex
        else:
            raise NotFoundError("{} is missing".format(key))
    return res
