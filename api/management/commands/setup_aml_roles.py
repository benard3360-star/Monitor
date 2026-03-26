from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.management.base import BaseCommand

from api.permissions import AML_ADMIN_GROUP, COMPLIANCE_OFFICER_GROUP


class Command(BaseCommand):
    help = "Create AML Admin / Compliance Officer groups and optionally a demo admin user."

    def add_arguments(self, parser):
        parser.add_argument(
            "--create-user",
            action="store_true",
            help="Create user amladmin / password ChangeMeNow! if missing (dev only).",
        )

    def handle(self, *args, **options):
        admin_g, _ = Group.objects.get_or_create(name=AML_ADMIN_GROUP)
        off_g, _ = Group.objects.get_or_create(name=COMPLIANCE_OFFICER_GROUP)
        self.stdout.write(self.style.SUCCESS(f"Groups ready: {AML_ADMIN_GROUP}, {COMPLIANCE_OFFICER_GROUP}"))

        if options["create_user"]:
            User = get_user_model()
            u, created = User.objects.get_or_create(
                username="amladmin",
                defaults={"email": "", "is_staff": True},
            )
            if created:
                u.set_password("ChangeMeNow!")
                u.save()
                self.stdout.write(self.style.WARNING("Created amladmin / ChangeMeNow! — change password immediately."))
            u.groups.add(admin_g)
            u.groups.add(off_g)
            self.stdout.write(self.style.SUCCESS(f"User {u.username} is in both groups."))
