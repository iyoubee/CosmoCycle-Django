# Generated by Django 4.1 on 2023-12-02 17:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0004_alter_deposit_username_alter_deposit_waste_type_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userdata',
            name='token',
            field=models.CharField(default='BVNIWS', max_length=10, unique=True),
        ),
    ]
