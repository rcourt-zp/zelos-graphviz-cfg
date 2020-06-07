from setuptools import setup

setup(
    name="zelos_graphviz_cfg",
    install_requires=[
        "zelos",
        "graphviz",
    ],
    entry_points={"zelos.plugins": ["zelos_graphviz_cfg=zelos_graphviz_cfg",],},
)