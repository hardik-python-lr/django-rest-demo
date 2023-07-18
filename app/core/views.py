from rest_framework.pagination import PageNumberPagination


class CustomPageNumberPagination(PageNumberPagination):
    """
    Pagination: Custom Page Number Pagination

    Overrides the default pagination class to enable dynamic pagination with a custom page size.

    Attributes:
        page_size_query_param (str): The name of the query parameter for setting the page size.

    """

    # Set the name of the query param
    page_size_query_param = 'size'
