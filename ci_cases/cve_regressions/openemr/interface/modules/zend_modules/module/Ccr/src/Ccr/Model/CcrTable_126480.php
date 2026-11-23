<?php
// CVE-2026-126480 mini repro (part 2/2): faithful sink body of
// CcrTable::insertApprovedData() (vulnerable v8_4_1, lines 297-375 of
// interface/modules/zend_modules/module/Ccr/src/Ccr/Model/CcrTable.php).
// The taint surface is the ARRAY KEYS of $data (= the whole $_REQUEST):
// 'patient_data<column>-sel' keys with value 'update' have their key
// suffix extracted via substr() and concatenated into the SET clause.
// Fix in 8.5.0: escape_sql_column_name($field_name, ['patient_data']...).
namespace Ccr\Model;

class CcrTable
{
    public function insertApprovedData($data)
    {
        $patient_data_fields = '';
        $patient_data_values = [];
        foreach ($data as $key => $val) {
            if (str_ends_with((string) $key, '-sel')) {
                if (is_array($val)) {
                    // array branch (lists1/lists2/prescriptions/immunizations
                    // INSERTs with all-bound values) omitted from the mini:
                    // those params are bound and are not the injection surface.
                } else {
                    if (str_starts_with((string) $key, 'patient_data')) {
                        if ($val == 'update') {
                            $var_name = substr((string) $key, 0, -4);
                            $field_name = substr($var_name, 13);
                            $patient_data_fields .= $field_name . '=?,';   // <-- raw concat of tainted key
                            array_push($patient_data_values, $data[$var_name]);
                        }
                    }
                }
            }
        }

        if (count($patient_data_values) > 0) {
            array_push($patient_data_values, $data['pid']);
            $patient_data_fields = substr($patient_data_fields, 0, -1);
            $query = "UPDATE patient_data SET $patient_data_fields WHERE pid=?";
            \OpenEMR\Common\Database\QueryUtils::sqlStatementThrowException($query, $patient_data_values);
        }
    }
}
