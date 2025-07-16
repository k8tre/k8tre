import re

from kubernetes_asyncio.client.models import V1EnvVar, V1ServicePort
from kubespawner import KubeSpawner
from tornado.web import HTTPError
from traitlets import List, Unicode
from secrets import token_urlsafe


def modify_pod_hook(spawner, pod):
    desktop_connection = spawner.desktop_connection
    desktop_image = spawner.desktop_image
    # desktop_username = spawner.desktop_username
    desktop_command = spawner.desktop_command

    if spawner.desktop_password is not None:
        desktop_password = spawner.desktop_password
    else:
        spawner.desktop_password = desktop_password = token_urlsafe(24)

    # First container is static-redirector, move user volume to user container
    pod.spec.containers[1].volume_mounts = pod.spec.containers[0].volume_mounts
    pod.spec.containers[0].volume_mounts = None

    # Move lifecycle hook to user container
    pod.spec.containers[1].lifecycle = pod.spec.containers[0].lifecycle
    pod.spec.containers[0].lifecycle = None

    # Desktop image
    pod.spec.containers[1].image = desktop_image

    # Set NEW_PASSWORD to override password if supported by image
    env_var = V1EnvVar(name="NEW_PASSWORD", value=desktop_password)
    if pod.spec.containers[1].env is None:
        pod.spec.containers[1].env = []
    pod.spec.containers[1].env.append(env_var)

    # chosen_profile = spawner.user_options.get("profile", "")
    pod.spec.containers[1].command = desktop_command

    if desktop_connection not in {"rdp", "vnc"}:
        raise ValueError(f"Invalid desktop_connection: {desktop_connection}")
    # spawner.log.info(f"{chosen_profile=} {pod.spec.containers[1].command=}")
    return pod


def _safe_dump(d):
    s = {}
    for k, v in d.items():
        if "password" in k:
            s[k] = "********"
        else:
            s[k] = v
    return s


# TODO: This should be moved into an independent repo and tested thoroughly since
# this touches some fairly low-level KubeSpawner areas
class KubeSpawnerGuac(KubeSpawner):
    desktop_connection = Unicode("Set by kubespawner_override")
    desktop_image = Unicode("Set by kubespawner_override")
    desktop_username = Unicode("Set by kubespawner_override")
    desktop_password = Unicode(None, allow_none=True)
    desktop_command = List(Unicode())

    def load_state(self, state):
        super().load_state(state)
        self.log.info(f"state={_safe_dump(state)}")

        for desktop_attr in (
            "desktop_connection",
            "desktop_image",
            "desktop_username",
            "desktop_password",
            "desktop_command",
        ):
            state_attr = state.get(desktop_attr)
        if state_attr:
            current_attr = getattr(self, desktop_attr)
            if current_attr and current_attr != state_attr:
                sanitised_attr = (
                    "********" if "password" in desktop_attr else state_attr
                )
                self.log.error(
                    f"Mismatch: {desktop_attr}={current_attr} state.{desktop_attr}={sanitised_attr}, not updating"
                )
            else:
                setattr(self, desktop_attr, state_attr)

    def get_state(self):
        state = super().get_state()
        for desktop_attr in (
            "desktop_connection",
            "desktop_image",
            "desktop_username",
            "desktop_password",
            "desktop_command",
        ):
            current_attr = getattr(self, desktop_attr)
            if current_attr:
                state[desktop_attr] = current_attr
        self.log.info(f"state={_safe_dump(state)}")
        return state

    def get_service_manifest(self, owner_reference):
        service = super().get_service_manifest(owner_reference)
        service.spec.ports.append(
            V1ServicePort(name="rdp", port=3389, target_port=3389)
        )
        service.spec.ports.append(
            V1ServicePort(name="vnc", port=5901, target_port=5901)
        )
        return service


# TODO: We should make require TRE projects to have a prefix to disinguish them from JupyterHub roles
# project_group_re = r"^project-[a-z0-9-]+$"
project_group_re = r"^.+$"
# egress_admin_groupname = "egress-admins"
# user_home_pvcname = "user-home-directories"
# user_egress_pvcname = "user-egress-directories"
# project_pvcname = "project-directories"
# egress_pvcname = "airlock-egress-directories"


# https://discourse.jupyter.org/t/tailoring-spawn-options-and-server-configuration-to-certain-users/8449
async def custom_options_form(spawner):
    spawner.profile_list = []
    username = spawner.user.name

    for group in spawner.user.groups:
        groupname = group.name
        if re.match(project_group_re, groupname):
            spawner.log.info(f"Adding {groupname} project storage for {username}.")
            pvc_name = f"project-{groupname}"
            common_overrides = {
                # Use the project as a shared volume for all users in project
                "pvc_name_template": pvc_name,
                # pvc_name_template is exapnded in the wrong place
                # https://github.com/jupyterhub/kubespawner/issues/761
                "pvc_name": pvc_name,
                "volumes": {
                    "home": {
                        "name": "home",
                        "persistentVolumeClaim": {
                            "claimName": pvc_name,
                        },
                    },
                },
                "volume_mounts": {
                    "home": {
                        "name": "home",
                        "mountPath": "/home/ubuntu",
                        "subPath": f"{username}",
                    },
                },
            }

            spawner.profile_list.append(
                {
                    "display_name": f"{groupname}-mate",
                    "slug": f"{groupname}-mate",
                    "kubespawner_override": {
                        **common_overrides,
                        "desktop_connection": "rdp",
                        "desktop_image": "ghcr.io/manics/ubuntu-mate-vncrdp:2025-07-16",
                        # "desktop_image": "ghcr.io/manics/ubuntu-mate-vncrdp:dev",
                        "desktop_username": "ubuntu",
                        "desktop_command": ["start-xrdp.sh"],
                    },
                }
            )
            spawner.profile_list.append(
                {
                    "display_name": f"{groupname}-mate (VNC)",
                    "slug": f"{groupname}-mate-vnc",
                    "kubespawner_override": {
                        **common_overrides,
                        "desktop_connection": "vnc",
                        "desktop_image": "ghcr.io/manics/ubuntu-mate-vncrdp:2025-07-16",
                        "desktop_username": "ubuntu",
                        "desktop_command": ["start-tigervnc.sh"],
                    },
                }
            )
            # spawner.profile_list.append(
            #     {
            #         "display_name": f"{groupname}-winxp",
            #         "slug": f"{groupname}-winxp",
            #         "kubespawner_override": {
            #             **common_overrides,
            #             "desktop_connection": "vnc",
            #             "desktop_image": "ghcr.io/manics/jupyter-desktop-winxp:latest",
            #             "desktop_username": "ubuntu",
            #             "desktop_command": ["start-tigervnc.sh"],
            #         },
            #     }
            # )

    #         if groupname == egress_admin_groupname:
    #             spawner.log.info(f"Adding {groupname} readonly storage for {username}.")
    #             spawner.profile_list.append(
    #                 {
    #                     "display_name": groupname,
    #                     "slug": groupname,
    #                     "kubespawner_override": {
    #                         "desktop_connection": desktop_connection,
    #                         "volumes": {
    #                             "home": {
    #                                 "name": "home",
    #                                 "persistentVolumeClaim": {
    #                                     "claimName": user_home_pvcname,
    #                                 },
    #                             },
    #                             "egress-review": {
    #                                 "name": "egress-review",
    #                                 "persistentVolumeClaim": {
    #                                     "claimName": egress_pvcname,
    #                                 },
    #                             },
    #                         },
    #                         "volume_mounts": {
    #                             "home": {
    #                                 "name": "home",
    #                                 "mountPath": f"/home/ubuntu",
    #                                 "subPath": f"{groupname}/{username}",
    #                             },
    #                             "egress-review": {
    #                                 "name": "egress-review",
    #                                 "mountPath": f"/home/ubuntu/egress-review",
    #                                 "readOnly": True,
    #                             },
    #                         },
    #                     },
    #                 }
    #             )

    if not spawner.profile_list:
        raise HTTPError(500, "No profiles found")
    return spawner._options_form_default()


c.KubeSpawner.modify_pod_hook = modify_pod_hook  # noqa: F821
c.JupyterHub.spawner_class = KubeSpawnerGuac  # noqa: F821
c.KubeSpawner.options_form = custom_options_form  # noqa: F821
