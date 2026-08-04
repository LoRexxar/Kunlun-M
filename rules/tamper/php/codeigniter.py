# -*- coding: utf-8 -*-
import os

FRAMEWORK_NAME = 'CodeIgniter'
DEPENDENCIES = {'composer': ['codeigniter4/framework']}


def detect(project_dir, language='php'):
    """检测是否为 CodeIgniter 项目"""
    return (os.path.isdir(os.path.join(project_dir, 'application', 'controllers'))
            or os.path.isdir(os.path.join(project_dir, 'app', 'Controllers')))


FILTER_FUNCTIONS = {
    '$this->security->xss_clean': {'safe_for': [1000, 1010]},
    '$this->db->escape': {'safe_for': [1004]},
    '$this->db->escape_str': {'safe_for': [1004]},
}

EXTRA_SINKS = [
    ("$this->db->query(", [1004]),
    ("->query(", [1004]),
    # View / Response — XSS
    ("view(", [1000]),
    ("->render(", [1000]),
    # Redirect
    ("redirect(", [1009]),
]

CONTROLLED_SOURCES = [
    '$this->input->get',
    '$this->input->post',
    '$this->input->cookie',
    '$this->request->getVar',
    '$this->request->getPost',
    '$this->request->getGet',
    '$this->request->getJSON',
    '$this->input->ip_address',
]
