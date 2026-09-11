# Generated manually for verification fields

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('index', '0014_taintchain'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanresulttask',
            name='verification_status',
            field=models.CharField(
                choices=[
                    ('pending', '待验证'),
                    ('tp', 'True Positive'),
                    ('fp', 'False Positive'),
                    ('unknown', '无法判断'),
                ],
                db_index=True,
                default='pending',
                max_length=10,
            ),
        ),
        migrations.AddField(
            model_name='scanresulttask',
            name='verified_by',
            field=models.CharField(default='', max_length=100),
        ),
        migrations.AddField(
            model_name='scanresulttask',
            name='verified_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='scanresulttask',
            name='verification_notes',
            field=models.TextField(default=''),
        ),
    ]
