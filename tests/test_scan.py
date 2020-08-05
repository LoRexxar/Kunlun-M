from core.engine import scan
from core.engine import init_match_rule
from Kunlun_M.settings import examples_path
from utils.log import logger
from phply import phpast as php


def test_scan():
    logger.info('Examples Path: {path}'.format(path=examples_path))
    assert scan(examples_path)

data = (php.Method(u'eval_function', [], [php.FormalParameter(u'$a', None, False, None)], [php.Eval(php.Variable(u'$a'))], False), php.Variable(u'$a'))


def test_init_match_rule():
    assert isinstance(init_match_rule(data), tuple)
    assert "eval_function" in init_match_rule(data)[1]
