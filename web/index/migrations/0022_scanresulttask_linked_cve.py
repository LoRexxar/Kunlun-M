# Generated manually for linked_cve feature (CVE tagging on vul list)

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('index', '0021_verdictevent'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanresulttask',
            name='linked_cve',
            field=models.CharField(blank=True, db_index=True, default='', max_length=40),
        ),
        migrations.AddField(
            model_name='scanresulttask',
            name='linked_cve_by',
            field=models.CharField(blank=True, default='', max_length=100),
        ),
    ]
